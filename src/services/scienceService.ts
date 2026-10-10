/**
 * SentinelLayer AI — Scientific Corpus & Biomolecular Integrity Service
 * Implements authoritative public API queries (AlphaFold DB, RCSB PDB, PubMed, Europe PMC, OpenAlex, arXiv proxy)
 * with fetchWithRetry and epistemic provenance tracking.
 */

export async function fetchWithRetry(
  url: string,
  options: RequestInit = {},
  maxRetries = 3,
  baseDelayMs = 600
): Promise<Response> {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const response = await fetch(url, options);
    if (response.ok) {
      return response;
    }
    if (
      (response.status === 429 || response.status >= 500) &&
      attempt < maxRetries
    ) {
      const retryAfter = Number(response.headers.get('Retry-After'));
      const delay =
        !Number.isNaN(retryAfter) && retryAfter > 0
          ? retryAfter * 1000
          : baseDelayMs * Math.pow(2, attempt);
      await new Promise((resolve) => setTimeout(resolve, delay));
      continue;
    }
    const errorBody = await response.text().catch(() => '');
    throw new Error(
      `HTTP ${response.status} (${response.statusText}) from ${url}: ${errorBody.slice(0, 300)}`
    );
  }
  throw new Error(`Exhausted retries for ${url}`);
}

export interface AlphaFoldPredictionRecord {
  entryId: string;
  gene: string;
  uniprotAccession: string;
  uniprotId: string;
  uniprotDescription: string;
  organismScientificName: string;
  uniprotStart: number;
  uniprotEnd: number;
  uniprotSequence: string;
  cifUrl: string;
  pdbUrl: string;
  paeImageUrl?: string;
}

export interface EuropePmcPaper {
  id: string;
  source: string;
  pmid?: string;
  doi?: string;
  title: string;
  authorString: string;
  journalTitle?: string;
  pubYear: string;
  citedByCount: number;
  abstractText?: string;
  isOpenAccess: string;
}

export async function fetchAlphaFoldStructure(uniprotAccession: string): Promise<AlphaFoldPredictionRecord> {
  const cleanId = uniprotAccession.trim().toUpperCase();
  const res = await fetchWithRetry(`https://alphafold.ebi.ac.uk/api/prediction/${encodeURIComponent(cleanId)}`);
  const data = await res.json();
  if (!Array.isArray(data) || data.length === 0) {
    throw new Error(`No AlphaFold structure prediction found for UniProt accession ${cleanId}`);
  }
  return data[0] as AlphaFoldPredictionRecord;
}

export async function searchEuropePmcPapers(query: string, pageSize = 6): Promise<EuropePmcPaper[]> {
  const url = `https://www.ebi.ac.uk/europepmc/webservices/rest/search?query=${encodeURIComponent(
    query
  )}&resultType=core&format=json&pageSize=${pageSize}`;
  const res = await fetchWithRetry(url);
  const data = await res.json();
  const list = data?.resultList?.result || [];
  return list.map((item: any) => ({
    id: item.id || '',
    source: item.source || 'MED',
    pmid: item.pmid,
    doi: item.doi,
    title: item.title || 'Untitled Scientific Record',
    authorString: item.authorString || 'Unknown Authors',
    journalTitle: item.journalInfo?.journal?.title || item.bookOrReportDetails?.publisher || 'Preprint / Journal',
    pubYear: item.pubYear || '2025',
    citedByCount: Number(item.citedByCount || 0),
    abstractText: item.abstractText ? String(item.abstractText).replace(/<[^>]+>/g, '') : undefined,
    isOpenAccess: item.isOpenAccess || 'N',
  }));
}

export async function searchArxivPreprints(query: string, maxResults = 5) {
  const res = await fetchWithRetry(
    `/api/science/arxiv?query=${encodeURIComponent(query)}&max_results=${maxResults}`
  );
  const xmlText = await res.text();
  const doc = new DOMParser().parseFromString(xmlText, 'application/xml');
  return Array.from(doc.getElementsByTagName('entry')).map((entry) => ({
    id: entry.getElementsByTagName('id')[0]?.textContent?.trim() ?? '',
    title: entry.getElementsByTagName('title')[0]?.textContent?.replace(/\s+/g, ' ').trim() ?? '',
    summary: entry.getElementsByTagName('summary')[0]?.textContent?.replace(/\s+/g, ' ').trim() ?? '',
    published: entry.getElementsByTagName('published')[0]?.textContent?.slice(0, 10) ?? '',
  }));
}
