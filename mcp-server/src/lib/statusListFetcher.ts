/**
 * IO boundary: fetch a StatusList2021 credential and extract the encodedList.
 */

export async function fetchStatusList(url: string): Promise<{ encodedList: string | null; error?: string }> {
  try {
    const response = await fetch(url, { headers: { Accept: "application/json" } });
    if (!response.ok) {
      return { encodedList: null, error: `HTTP ${response.status}` };
    }

    const data = await response.json() as Record<string, unknown>;

    // Status list may be a raw VC or a JWT-encoded VC
    // Handle JSON-LD format: data.credentialSubject.encodedList
    const subject = (data as { credentialSubject?: { encodedList?: string } }).credentialSubject;
    if (subject?.encodedList) {
      return { encodedList: subject.encodedList };
    }

    // Handle VC wrapper: data.vc.credentialSubject.encodedList
    const vc = (data as { vc?: { credentialSubject?: { encodedList?: string } } }).vc;
    if (vc?.credentialSubject?.encodedList) {
      return { encodedList: vc.credentialSubject.encodedList };
    }

    return { encodedList: null, error: "No encodedList found in status list credential" };
  } catch (err) {
    return { encodedList: null, error: String(err) };
  }
}
