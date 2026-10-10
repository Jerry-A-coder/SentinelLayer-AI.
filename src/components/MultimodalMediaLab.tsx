import React, { useState, useRef } from 'react';
import {
  Mic,
  MicOff,
  MessageSquareCode,
  Image as ImageIcon,
  Film,
  ScanEye,
  Volume2,
  Send,
  RefreshCw,
  Upload,
  Sparkles,
  FileAudio,
  MapPin,
  ExternalLink,
  ShieldCheck,
} from 'lucide-react';

export const MultimodalMediaLab: React.FC<{
  onSendExtractedToFirewall: (text: string, sourceName: string) => void;
}> = ({ onSendExtractedToFirewall }) => {
  // 1. Multi-Turn Security Advisor Chatbot (gemini-3.1-pro-preview w/ HIGH thinking, gemini-3.5-flash, gemini-3.1-flash-lite)
  const [chatMessages, setChatMessages] = useState<{ role: 'user' | 'model'; text: string; meta?: string }[]>([
    {
      role: 'model',
      text: 'SentinelLayer AI Principal Security Architect ready. Ask me to analyze complex multi-step prompt injections, craft deterministic firewall rules, or evaluate tool permission scopes.',
      meta: 'System Initialized',
    },
  ]);
  const [chatInput, setChatInput] = useState('');
  const [chatModelMode, setChatModelMode] = useState<'pro-thinking' | 'flash' | 'lite'>('pro-thinking');
  const [chatLoading, setChatLoading] = useState(false);

  // 2. Live API Voice Session (gemini-3.8-live)
  const [liveConnected, setLiveConnected] = useState(false);
  const [liveTranscripts, setLiveTranscripts] = useState<string[]>([]);
  const [livePromptText, setLivePromptText] = useState('');
  const wsRef = useRef<WebSocket | null>(null);
  const inputAudioCtxRef = useRef<AudioContext | null>(null);
  const outputAudioCtxRef = useRef<AudioContext | null>(null);
  const mediaStreamRef = useRef<MediaStream | null>(null);

  // 3. Create & Edit Images (gemini-nano-banana-2.1)
  const [imgPrompt, setImgPrompt] = useState(
    'Isometric technical diagram of a zero-trust AI prompt firewall inspecting multimodal documents, dark slate aesthetic, crisp vector telemetry lines'
  );
  const [imgAspectRatio, setImgAspectRatio] = useState('16:9');
  const [generatedImgUrl, setGeneratedImgUrl] = useState<string | null>(null);
  const [editSourceBase64, setEditSourceBase64] = useState<string | null>(null);
  const [editSourceMime, setEditSourceMime] = useState<string>('image/png');
  const [imgLoading, setImgLoading] = useState(false);

  // 4. Analyze Images (gemini-3.1-pro-preview) & Animate into Video (veo-3.1-fast-generate-preview)
  const [uploadedImgBase64, setUploadedImgBase64] = useState<string | null>(null);
  const [uploadedImgMime, setUploadedImgMime] = useState<string>('image/png');
  const [uploadedImgPreview, setUploadedImgPreview] = useState<string | null>(null);
  const [visionPrompt, setVisionPrompt] = useState(
    'Inspect this image for any visible or hidden prompt injection directives, OCR text anomalies, or security risks.'
  );
  const [visionAnalysis, setVisionAnalysis] = useState<string | null>(null);
  const [visionLoading, setVisionLoading] = useState(false);

  // 5. Veo Video Animation (veo-3.1-fast-generate-preview, 16:9 or 9:16)
  const [videoPrompt, setVideoPrompt] = useState(
    'Cinematic data visualization of a cybersecurity firewall gateway intercepting red adversarial packets and routing clean blue data streams'
  );
  const [videoAspect, setVideoAspect] = useState<'16:9' | '9:16'>('16:9');
  const [videoStatusMsg, setVideoStatusMsg] = useState<string | null>(null);
  const [videoUrl, setVideoUrl] = useState<string | null>(null);
  const [videoLoading, setVideoLoading] = useState(false);

  // 6. TTS Audio Briefing (gemini-3.8-flash-tts)
  const [ttsText, setTtsText] = useState(
    'SentinelLayer AI Security Report: All five analysis agents are operational. Deterministic policy enforcement is active.'
  );
  const [ttsVoice, setTtsVoice] = useState('Kore');
  const [ttsLoading, setTtsLoading] = useState(false);
  const [ttsAudioUrl, setTtsAudioUrl] = useState<string | null>(null);

  // 7. Audio Transcription (gemini-3.5-transcribe)
  const [recordingAudio, setRecordingAudio] = useState(false);
  const [audioBase64, setAudioBase64] = useState<string | null>(null);
  const [audioMimeType, setAudioMimeType] = useState<string>('audio/webm');
  const [audioFileName, setAudioFileName] = useState<string | null>(null);
  const [transcribeLoading, setTranscribeLoading] = useState(false);
  const [transcribedText, setTranscribedText] = useState<string | null>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);

  // 8. Google Maps Grounding (gemini-3.8-flash + googleMaps tool)
  const [mapsQuery, setMapsQuery] = useState(
    'Cybersecurity incident response centers, cloud data center hubs, and technology campuses in San Francisco, CA'
  );
  const [mapsLoading, setMapsLoading] = useState(false);
  const [mapsBriefing, setMapsBriefing] = useState<string | null>(null);
  const [mapsPlaces, setMapsPlaces] = useState<
    { title: string; uri: string; reviewSnippets?: string[] }[]
  >([]);
  const [userCoords, setUserCoords] = useState<{ latitude: number; longitude: number } | null>(null);

  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // --- Handlers ---
  const handleSendChat = async () => {
    if (!chatInput.trim() || chatLoading) return;
    const nextHistory = [...chatMessages, { role: 'user' as const, text: chatInput }];
    setChatMessages(nextHistory);
    setChatInput('');
    setChatLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch('/api/chat/security-advisor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: nextHistory.map((m) => ({ role: m.role, text: m.text })),
          modelMode: chatModelMode,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Chat request failed');
      setChatMessages([
        ...nextHistory,
        {
          role: 'model',
          text: data.reply,
          meta: `${data.modelUsed} · Thinking: ${data.thinkingLevel}`,
        },
      ]);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Advisor chat error');
    } finally {
      setChatLoading(false);
    }
  };

  // Helper to convert Float32 mic audio to base64 16-bit PCM
  const pcmToBase64 = (float32Array: Float32Array): string => {
    const int16Array = new Int16Array(float32Array.length);
    for (let i = 0; i < float32Array.length; i++) {
      const s = Math.max(-1, Math.min(1, float32Array[i]));
      int16Array[i] = s < 0 ? s * 0x8000 : s * 0x7fff;
    }
    const bytes = new Uint8Array(int16Array.buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  };

  const playPcmChunk = (ctx: AudioContext, base64Data: string) => {
    try {
      const binary = atob(base64Data);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      const int16 = new Int16Array(bytes.buffer);
      const float32 = new Float32Array(int16.length);
      for (let i = 0; i < int16.length; i++) {
        float32[i] = int16[i] / 32768.0;
      }
      const buffer = ctx.createBuffer(1, float32.length, 24000);
      buffer.getChannelData(0).set(float32);
      const source = ctx.createBufferSource();
      source.buffer = buffer;
      source.connect(ctx.destination);
      source.start();
    } catch {
      // Ignore audio decode glitch
    }
  };

  const toggleLiveVoiceSession = async () => {
    if (liveConnected) {
      wsRef.current?.close();
      mediaStreamRef.current?.getTracks().forEach((t) => t.stop());
      inputAudioCtxRef.current?.close();
      outputAudioCtxRef.current?.close();
      setLiveConnected(false);
      return;
    }

    setErrorMsg(null);
    try {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(`${proto}//${window.location.host}/live`);
      wsRef.current = ws;

      const outCtx = new AudioContext({ sampleRate: 24000 });
      outputAudioCtxRef.current = outCtx;

      ws.onopen = async () => {
        setLiveConnected(true);
        setLiveTranscripts((prev) => [...prev, '[Connected to gemini-3.8-live real-time voice bridge]']);
        try {
          const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
          mediaStreamRef.current = stream;
          const inCtx = new AudioContext({ sampleRate: 16000 });
          inputAudioCtxRef.current = inCtx;
          const source = inCtx.createMediaStreamSource(stream);
          const processor = inCtx.createScriptProcessor(4096, 1, 1);
          source.connect(processor);
          processor.connect(inCtx.destination);
          processor.onaudioprocess = (e) => {
            if (ws.readyState === WebSocket.OPEN) {
              const b64 = pcmToBase64(e.inputBuffer.getChannelData(0));
              ws.send(JSON.stringify({ audio: b64 }));
            }
          };
        } catch {
          setLiveTranscripts((prev) => [
            ...prev,
            '[Microphone permission not active — you can still send real-time turns using the text prompt box below]',
          ]);
        }
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.audio && outputAudioCtxRef.current) {
            playPcmChunk(outputAudioCtxRef.current, msg.audio);
          }
          if (msg.transcript) {
            setLiveTranscripts((prev) => [...prev, `Commander: ${msg.transcript}`]);
          }
          if (msg.error) {
            setErrorMsg(msg.error);
          }
        } catch {
          // Ignore
        }
      };

      ws.onclose = () => {
        setLiveConnected(false);
      };
    } catch (err: any) {
      setErrorMsg(err?.message || 'Could not start Live API session');
    }
  };

  const sendLiveTextTurn = () => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN || !livePromptText.trim()) return;
    wsRef.current.send(JSON.stringify({ text: livePromptText }));
    setLiveTranscripts((prev) => [...prev, `You: ${livePromptText}`]);
    setLivePromptText('');
  };

  const handleGenerateOrEditImage = async () => {
    if (!imgPrompt.trim() || imgLoading) return;
    setImgLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch('/api/media/generate-image', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prompt: imgPrompt,
          aspectRatio: imgAspectRatio,
          sourceImageBase64: editSourceBase64,
          sourceImageMimeType: editSourceMime,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Image generation failed');
      setGeneratedImgUrl(data.imageUrl);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Image generation failed');
    } finally {
      setImgLoading(false);
    }
  };

  const handleFileUpload = (
    e: React.ChangeEvent<HTMLInputElement>,
    target: 'forensic' | 'edit'
  ) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = String(reader.result);
      const commaIdx = dataUrl.indexOf(',');
      const b64 = commaIdx >= 0 ? dataUrl.slice(commaIdx + 1) : dataUrl;
      if (target === 'forensic') {
        setUploadedImgBase64(b64);
        setUploadedImgMime(file.type || 'image/png');
        setUploadedImgPreview(dataUrl);
      } else {
        setEditSourceBase64(b64);
        setEditSourceMime(file.type || 'image/png');
      }
    };
    reader.readAsDataURL(file);
  };

  const handleAnalyzeImage = async () => {
    if (!uploadedImgBase64 || visionLoading) return;
    setVisionLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch('/api/media/analyze-image', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          imageBase64: uploadedImgBase64,
          imageMimeType: uploadedImgMime,
          prompt: visionPrompt,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Image analysis failed');
      setVisionAnalysis(data.analysis);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Image analysis failed');
    } finally {
      setVisionLoading(false);
    }
  };

  const handleGenerateVeoVideo = async () => {
    if (videoLoading) return;
    setVideoLoading(true);
    setVideoUrl(null);
    setErrorMsg(null);
    setVideoStatusMsg('Submitting video generation task to veo-3.1-fast-generate-preview...');
    try {
      const startRes = await fetch('/api/video/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prompt: videoPrompt,
          aspectRatio: videoAspect,
          imageBase64: uploadedImgBase64 || undefined,
          imageMimeType: uploadedImgMime || 'image/png',
        }),
      });
      const startData = await startRes.json();
      if (!startRes.ok) throw new Error(startData.error || 'Failed to start Veo generation');

      const operationName = startData.operationName;
      setVideoStatusMsg('Synthesizing frames with Veo 3.1 Fast... Polling operation status...');

      let done = false;
      for (let i = 0; i < 40; i++) {
        await new Promise((r) => setTimeout(r, 5000));
        const pollRes = await fetch('/api/video/status', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ operationName }),
        });
        const pollData = await pollRes.json();
        if (pollData.done) {
          done = true;
          break;
        }
        setVideoStatusMsg(`Rendering threat simulation video... (${(i + 1) * 5}s elapsed)`);
      }

      if (!done) {
        throw new Error('Video generation timed out waiting for completion.');
      }

      setVideoStatusMsg('Downloading generated MP4 stream...');
      const dlRes = await fetch('/api/video/download', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operationName }),
      });
      if (!dlRes.ok) throw new Error('Failed to download generated video');
      const blob = await dlRes.blob();
      setVideoUrl(URL.createObjectURL(blob));
      setVideoStatusMsg(null);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Video generation failed');
      setVideoStatusMsg(null);
    } finally {
      setVideoLoading(false);
    }
  };

  const handleGenerateTts = async () => {
    if (!ttsText.trim() || ttsLoading) return;
    setTtsLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch('/api/tts/briefing', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: ttsText, voiceName: ttsVoice }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'TTS failed');
      setTtsAudioUrl(`data:audio/wav;base64,${data.audioBase64}`);
    } catch (err: any) {
      setErrorMsg(err?.message || 'TTS generation failed');
    } finally {
      setTtsLoading(false);
    }
  };

  const handleAudioFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setAudioFileName(file.name);
    setAudioMimeType(file.type || 'audio/mp3');
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = String(reader.result);
      const commaIdx = dataUrl.indexOf(',');
      const b64 = commaIdx >= 0 ? dataUrl.slice(commaIdx + 1) : dataUrl;
      setAudioBase64(b64);
    };
    reader.readAsDataURL(file);
  };

  const toggleMicAudioRecording = async () => {
    if (recordingAudio) {
      mediaRecorderRef.current?.stop();
      setRecordingAudio(false);
      return;
    }
    setErrorMsg(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const recorder = new MediaRecorder(stream);
      mediaRecorderRef.current = recorder;
      audioChunksRef.current = [];
      recorder.ondataavailable = (ev) => {
        if (ev.data.size > 0) audioChunksRef.current.push(ev.data);
      };
      recorder.onstop = () => {
        const blob = new Blob(audioChunksRef.current, { type: recorder.mimeType || 'audio/webm' });
        setAudioMimeType(recorder.mimeType || 'audio/webm');
        setAudioFileName('Recorded_Voice_Briefing.webm');
        const reader = new FileReader();
        reader.onloadend = () => {
          const dataUrl = String(reader.result);
          const commaIdx = dataUrl.indexOf(',');
          setAudioBase64(commaIdx >= 0 ? dataUrl.slice(commaIdx + 1) : dataUrl);
        };
        reader.readAsDataURL(blob);
        stream.getTracks().forEach((t) => t.stop());
      };
      recorder.start();
      setRecordingAudio(true);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Microphone access unavailable for recording.');
    }
  };

  const handleTranscribeAudio = async () => {
    if (!audioBase64 || transcribeLoading) return;
    setTranscribeLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch('/api/audio/transcribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          audioBase64,
          mimeType: audioMimeType,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Audio transcription failed');
      setTranscribedText(data.transcript);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Audio transcription error');
    } finally {
      setTranscribeLoading(false);
    }
  };

  const handleUseMyLocationForMaps = () => {
    if (!navigator.geolocation) return;
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setUserCoords({
          latitude: pos.coords.latitude,
          longitude: pos.coords.longitude,
        });
      },
      () => {
        // Ignore geolocation denial
      }
    );
  };

  const handleSearchMapsGrounding = async () => {
    if (!mapsQuery.trim() || mapsLoading) return;
    setMapsLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch('/api/intelligence/maps-grounding', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: mapsQuery,
          latitude: userCoords?.latitude,
          longitude: userCoords?.longitude,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Google Maps grounding failed');
      setMapsBriefing(data.briefing);
      setMapsPlaces(data.places || []);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Google Maps grounding error');
    } finally {
      setMapsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {errorMsg && (
        <div className="p-4 bg-red-950/60 border border-red-800 rounded-xl text-xs text-red-200">
          {errorMsg}
        </div>
      )}

      {/* Row 1: Multi-Turn Security Advisor Chatbot + Real-Time Live Voice Commander */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Multi-Turn Gemini Security Chatbot */}
        <div className="lg:col-span-7 p-5 bg-slate-900/90 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                  <MessageSquareCode className="w-5 h-5 text-sky-400" />
                  <span>Multi-Turn Security Architect Chatbot</span>
                </h3>
                <p className="text-xs text-slate-400">
                  Switch between Deep Thinking (gemini-3.1-pro-preview + ThinkingLevel.HIGH), Standard (gemini-3.5-flash), and Fast Triage (gemini-3.1-flash-lite).
                </p>
              </div>
              <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-lg">
                <button
                  onClick={() => setChatModelMode('pro-thinking')}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    chatModelMode === 'pro-thinking'
                      ? 'bg-sky-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Pro (High Thinking)
                </button>
                <button
                  onClick={() => setChatModelMode('flash')}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    chatModelMode === 'flash'
                      ? 'bg-sky-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  3.5 Flash
                </button>
                <button
                  onClick={() => setChatModelMode('lite')}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    chatModelMode === 'lite'
                      ? 'bg-sky-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  3.1 Flash Lite
                </button>
              </div>
            </div>

            <div className="h-72 overflow-y-auto p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-3">
              {chatMessages.map((m, idx) => (
                <div
                  key={idx}
                  className={`p-3 rounded-lg text-xs leading-relaxed ${
                    m.role === 'user'
                      ? 'bg-sky-950/60 border border-sky-800/60 text-sky-100 ml-8'
                      : 'bg-slate-900 border border-slate-800 text-slate-200 mr-8'
                  }`}
                >
                  {m.meta && (
                    <div className="text-[11px] font-mono text-slate-400 mb-1">{m.meta}</div>
                  )}
                  <div className="whitespace-pre-wrap">{m.text}</div>
                </div>
              ))}
              {chatLoading && (
                <div className="text-xs text-sky-400 font-mono animate-pulse px-2">
                  Reasoning with {chatModelMode === 'pro-thinking' ? 'gemini-3.1-pro-preview (ThinkingLevel.HIGH)' : chatModelMode}...
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="text"
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSendChat()}
              placeholder="Ask about multistep jailbreaks, tool scope rules, or indirect injection..."
              className="flex-1 px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-100"
            />
            <button
              onClick={handleSendChat}
              disabled={chatLoading}
              className="px-4 py-2 text-xs font-medium bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg flex items-center gap-1.5 whitespace-nowrap shrink-0"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Send</span>
            </button>
          </div>
        </div>

        {/* Live API Voice Commander (gemini-3.8-live) + TTS Briefing (gemini-3.8-flash-tts) */}
        <div className="lg:col-span-5 p-5 bg-slate-900/90 border border-slate-800 rounded-xl flex flex-col justify-between space-y-5">
          {/* Live API Box */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                  <Mic className="w-4 h-4 text-emerald-400" />
                  <span>Live Voice Security Bridge (gemini-3.8-live)</span>
                </h3>
                <p className="text-xs text-slate-400">
                  Real-time bidirectional voice & audio conversation over WebSocket.
                </p>
              </div>
              <button
                onClick={toggleLiveVoiceSession}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 ${
                  liveConnected
                    ? 'bg-red-600 hover:bg-red-500 text-white'
                    : 'bg-emerald-600 hover:bg-emerald-500 text-white'
                }`}
              >
                {liveConnected ? <MicOff className="w-3.5 h-3.5" /> : <Mic className="w-3.5 h-3.5" />}
                <span>{liveConnected ? 'Disconnect Live' : 'Start Live Voice'}</span>
              </button>
            </div>

            <div className="h-32 overflow-y-auto p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 space-y-1">
              {liveTranscripts.length === 0 ? (
                <div className="text-slate-500">
                  Click "Start Live Voice" to open a real-time WebSocket audio session with gemini-3.8-live.
                </div>
              ) : (
                liveTranscripts.map((t, i) => <div key={i}>{t}</div>)
              )}
            </div>

            {liveConnected && (
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={livePromptText}
                  onChange={(e) => setLivePromptText(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && sendLiveTextTurn()}
                  placeholder="Speak into mic or send live prompt..."
                  className="flex-1 px-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-100"
                />
                <button
                  onClick={sendLiveTextTurn}
                  className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg"
                >
                  Send Turn
                </button>
              </div>
            )}
          </div>

          {/* TTS Audio Briefing (gemini-3.8-flash-tts) */}
          <div className="pt-4 border-t border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Volume2 className="w-4 h-4 text-sky-400" />
                <span>Convert Security Report to Speech (gemini-3.8-flash-tts)</span>
              </h4>
              <select
                value={ttsVoice}
                onChange={(e) => setTtsVoice(e.target.value)}
                className="px-2 py-1 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200"
              >
                <option value="Kore">Voice: Kore</option>
                <option value="Puck">Voice: Puck</option>
                <option value="Zephyr">Voice: Zephyr</option>
                <option value="Charon">Voice: Charon</option>
              </select>
            </div>
            <textarea
              rows={2}
              value={ttsText}
              onChange={(e) => setTtsText(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200"
            />
            <div className="flex items-center justify-between gap-3">
              <button
                onClick={handleGenerateTts}
                disabled={ttsLoading}
                className="px-3 py-1.5 text-xs font-medium bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg flex items-center gap-1.5 whitespace-nowrap shrink-0"
              >
                <Volume2 className="w-3.5 h-3.5" />
                <span>{ttsLoading ? 'Synthesizing WAV...' : 'Synthesize Speech'}</span>
              </button>
              {ttsAudioUrl && (
                <audio controls src={ttsAudioUrl} className="h-8 flex-1" />
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Row 2: Image Forensics (gemini-3.1-pro-preview) + Veo Video Simulation (veo-3.1-fast-generate-preview) + Image Studio (gemini-nano-banana-2.1) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Upload & Analyze Image + Animate into Video */}
        <div className="lg:col-span-6 p-5 bg-slate-900/90 border border-slate-800 rounded-xl space-y-4">
          <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <ScanEye className="w-5 h-5 text-sky-400" />
            <span>Visual Steganography Forensics & Veo Video Animation</span>
          </h3>
          <p className="text-xs text-slate-400">
            Upload a document screenshot or photo to inspect with <code className="text-slate-300">gemini-3.1-pro-preview</code> or animate into a threat replay video using <code className="text-slate-300">veo-3.1-fast-generate-preview</code>.
          </p>

          <div className="flex flex-wrap items-center gap-3">
            <label className="px-3 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg cursor-pointer flex items-center gap-2 whitespace-nowrap shrink-0">
              <Upload className="w-3.5 h-3.5" />
              <span>Upload Photo / Screenshot</span>
              <input
                type="file"
                accept="image/*"
                onChange={(e) => handleFileUpload(e, 'forensic')}
                className="hidden"
              />
            </label>
            <button
              onClick={handleAnalyzeImage}
              disabled={!uploadedImgBase64 || visionLoading}
              className="px-3 py-2 text-xs font-medium bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg flex items-center gap-1.5 whitespace-nowrap shrink-0"
            >
              <ScanEye className="w-3.5 h-3.5" />
              <span>{visionLoading ? 'Analyzing Image...' : 'Analyze with Gemini 3.1 Pro'}</span>
            </button>
          </div>

          {uploadedImgPreview && (
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg flex items-center gap-4">
              <img
                src={uploadedImgPreview}
                alt="Uploaded target"
                referrerPolicy="no-referrer"
                className="w-24 h-24 object-cover rounded border border-slate-700"
              />
              <div className="flex-1 space-y-2">
                <input
                  type="text"
                  value={visionPrompt}
                  onChange={(e) => setVisionPrompt(e.target.value)}
                  className="w-full px-2.5 py-1.5 text-xs bg-slate-900 border border-slate-800 rounded text-slate-200"
                />
                {visionAnalysis && (
                  <div className="space-y-1.5">
                    <div className="text-xs text-slate-300 max-h-28 overflow-y-auto whitespace-pre-wrap">
                      {visionAnalysis}
                    </div>
                    <button
                      onClick={() =>
                        onSendExtractedToFirewall(visionAnalysis, 'Image OCR / Vision Inspection')
                      }
                      className="px-2.5 py-1 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded"
                    >
                      Run Extracted Image Text Through Firewall
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Veo 3.1 Fast Video Generation Controls */}
          <div className="pt-3 border-t border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <Film className="w-4 h-4 text-amber-400" />
                <span>Animate Threat Topology into Video (veo-3.1-fast-generate-preview)</span>
              </span>
              <div className="flex items-center gap-1 bg-slate-950 p-1 rounded border border-slate-800">
                <button
                  onClick={() => setVideoAspect('16:9')}
                  className={`px-2 py-0.5 text-xs rounded ${
                    videoAspect === '16:9' ? 'bg-amber-600 text-white' : 'text-slate-400'
                  }`}
                >
                  16:9 Landscape
                </button>
                <button
                  onClick={() => setVideoAspect('9:16')}
                  className={`px-2 py-0.5 text-xs rounded ${
                    videoAspect === '9:16' ? 'bg-amber-600 text-white' : 'text-slate-400'
                  }`}
                >
                  9:16 Portrait
                </button>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={videoPrompt}
                onChange={(e) => setVideoPrompt(e.target.value)}
                placeholder="Describe video animation..."
                className="flex-1 px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200"
              />
              <button
                onClick={handleGenerateVeoVideo}
                disabled={videoLoading}
                className="px-3 py-2 text-xs font-medium bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white rounded-lg flex items-center gap-1.5 whitespace-nowrap shrink-0"
              >
                <Film className="w-3.5 h-3.5" />
                <span>{videoLoading ? 'Generating...' : 'Generate Video'}</span>
              </button>
            </div>
            {videoStatusMsg && (
              <div className="text-xs font-mono text-amber-300 animate-pulse">{videoStatusMsg}</div>
            )}
            {videoUrl && (
              <video
                controls
                src={videoUrl}
                className="w-full max-h-56 rounded-lg border border-slate-800 bg-black"
              />
            )}
          </div>
        </div>

        {/* Create & Edit Images (gemini-nano-banana-2.1) */}
        <div className="lg:col-span-6 p-5 bg-slate-900/90 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <ImageIcon className="w-5 h-5 text-sky-400" />
                <span>Security Diagram & Visual Sandbox (gemini-nano-banana-2.1)</span>
              </h3>
              <select
                value={imgAspectRatio}
                onChange={(e) => setImgAspectRatio(e.target.value)}
                className="px-2.5 py-1 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200"
              >
                <option value="16:9">16:9</option>
                <option value="1:1">1:1</option>
                <option value="4:3">4:3</option>
                <option value="9:16">9:16</option>
              </select>
            </div>
            <p className="text-xs text-slate-400">
              Create or edit security architecture diagrams or synthetic test images using <code className="text-slate-300">gemini-nano-banana-2.1</code>.
            </p>
            <textarea
              rows={2}
              value={imgPrompt}
              onChange={(e) => setImgPrompt(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200"
            />
            <div className="flex flex-wrap items-center gap-3">
              <label className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg cursor-pointer flex items-center gap-1.5 whitespace-nowrap shrink-0">
                <Upload className="w-3.5 h-3.5" />
                <span>{editSourceBase64 ? 'Reference Image Loaded' : 'Optional Image to Edit'}</span>
                <input
                  type="file"
                  accept="image/*"
                  onChange={(e) => handleFileUpload(e, 'edit')}
                  className="hidden"
                />
              </label>
              <button
                onClick={handleGenerateOrEditImage}
                disabled={imgLoading}
                className="px-4 py-1.5 text-xs font-medium bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg flex items-center gap-1.5 whitespace-nowrap shrink-0"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>{imgLoading ? 'Rendering with Nano Banana 2.1...' : 'Create / Edit Image'}</span>
              </button>
            </div>
          </div>

          {generatedImgUrl ? (
            <div className="p-2 bg-slate-950 border border-slate-800 rounded-lg">
              <img
                src={generatedImgUrl}
                alt="Generated security visual"
                referrerPolicy="no-referrer"
                className="w-full max-h-60 object-contain rounded"
              />
            </div>
          ) : (
            <div className="p-8 bg-slate-950 border border-slate-800/80 rounded-lg text-xs text-slate-500 text-center">
              Generated or edited visuals from gemini-nano-banana-2.1 will render here.
            </div>
          )}
        </div>
      </div>

      {/* Row 3: Forensic Audio Transcription (gemini-3.5-transcribe) + Geospatial Facility & SOC Grounding (Google Maps Grounding) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Audio Transcription Card (gemini-3.5-transcribe) */}
        <div className="lg:col-span-6 p-5 bg-slate-900/90 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <FileAudio className="w-5 h-5 text-emerald-400" />
                <span>Forensic Audio Transcription (gemini-3.5-transcribe)</span>
              </h3>
              <span className="text-xs font-mono text-emerald-400">Audio → Firewall</span>
            </div>
            <p className="text-xs text-slate-400">
              Record a live voice memo or upload an audio clip (<code className="text-slate-300">.mp3</code>, <code className="text-slate-300">.wav</code>, <code className="text-slate-300">.webm</code>) to transcribe with <code className="text-slate-300">gemini-3.5-transcribe</code> and scan for spoken prompt injection directives.
            </p>

            <div className="flex flex-wrap items-center gap-2.5">
              <button
                onClick={toggleMicAudioRecording}
                className={`px-3 py-2 text-xs font-medium rounded-lg flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 ${
                  recordingAudio
                    ? 'bg-red-600 hover:bg-red-500 text-white animate-pulse'
                    : 'bg-slate-800 hover:bg-slate-700 text-slate-200'
                }`}
              >
                {recordingAudio ? <MicOff className="w-3.5 h-3.5" /> : <Mic className="w-3.5 h-3.5" />}
                <span>{recordingAudio ? 'Stop Recording' : 'Record Voice Clip'}</span>
              </button>

              <label className="px-3 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg cursor-pointer flex items-center gap-1.5 whitespace-nowrap shrink-0">
                <Upload className="w-3.5 h-3.5" />
                <span>{audioFileName ? audioFileName : 'Upload Audio File'}</span>
                <input
                  type="file"
                  accept="audio/*"
                  onChange={handleAudioFileUpload}
                  className="hidden"
                />
              </label>

              <button
                onClick={handleTranscribeAudio}
                disabled={!audioBase64 || transcribeLoading}
                className="px-3.5 py-2 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg flex items-center gap-1.5 whitespace-nowrap shrink-0"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${transcribeLoading ? 'animate-spin' : ''}`} />
                <span>{transcribeLoading ? 'Transcribing...' : 'Transcribe Audio'}</span>
              </button>
            </div>

            {transcribedText !== null && (
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-2.5">
                <div className="text-xs font-semibold text-slate-300">
                  Transcript Output (gemini-3.5-transcribe):
                </div>
                <div className="text-xs text-slate-200 whitespace-pre-wrap max-h-36 overflow-y-auto font-mono">
                  {transcribedText || 'No speech detected in audio.'}
                </div>
                {transcribedText && (
                  <button
                    onClick={() =>
                      onSendExtractedToFirewall(
                        transcribedText,
                        audioFileName || 'Transcribed Voice Clip'
                      )
                    }
                    className="px-3 py-1.5 text-xs font-medium bg-sky-600 hover:bg-sky-500 text-white rounded-lg flex items-center gap-1.5"
                  >
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Inspect Transcript in Prompt Firewall</span>
                  </button>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Google Maps Grounding Card (gemini-3.8-flash + googleMaps) */}
        <div className="lg:col-span-6 p-5 bg-slate-900/90 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <MapPin className="w-5 h-5 text-sky-400" />
                <span>Geospatial SOC & Facility Grounding (Google Maps)</span>
              </h3>
              <button
                onClick={handleUseMyLocationForMaps}
                className="px-2.5 py-1 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg flex items-center gap-1 whitespace-nowrap shrink-0"
              >
                <MapPin className="w-3 h-3 text-sky-400" />
                <span>
                  {userCoords
                    ? `Lat ${userCoords.latitude.toFixed(2)}, Lng ${userCoords.longitude.toFixed(2)}`
                    : 'Use My Location'}
                </span>
              </button>
            </div>
            <p className="text-xs text-slate-400">
              Query verified physical locations, data center regions, and incident response facilities with <code className="text-slate-300">gemini-3.8-flash</code> grounded in real-time Google Maps data.
            </p>

            <div className="flex items-center gap-2">
              <input
                type="text"
                value={mapsQuery}
                onChange={(e) => setMapsQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearchMapsGrounding()}
                placeholder="Search data centers, security offices, or infrastructure locations..."
                className="flex-1 px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-100"
              />
              <button
                onClick={handleSearchMapsGrounding}
                disabled={mapsLoading}
                className="px-3.5 py-2 text-xs font-medium bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg flex items-center gap-1.5 whitespace-nowrap shrink-0"
              >
                <MapPin className="w-3.5 h-3.5" />
                <span>{mapsLoading ? 'Grounding...' : 'Query Maps'}</span>
              </button>
            </div>

            {mapsBriefing && (
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-2.5 max-h-56 overflow-y-auto">
                <div className="text-xs text-slate-200 whitespace-pre-wrap leading-relaxed">
                  {mapsBriefing}
                </div>
                {mapsPlaces.length > 0 && (
                  <div className="pt-2 border-t border-slate-800 space-y-1.5">
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                      Verified Google Maps Grounding Links
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {mapsPlaces.map((place, idx) => (
                        <a
                          key={idx}
                          href={place.uri}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="px-2.5 py-1 text-xs bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded text-sky-400 flex items-center gap-1.5"
                        >
                          <span>{place.title}</span>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
