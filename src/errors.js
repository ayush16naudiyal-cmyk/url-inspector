// One error type for everything the API can report to the user.
// - status: the HTTP status the API should answer with (400 = bad input, 502 = target site problem)
// - phase:  which step failed ("dns", "tcp", "tls", ...), so the UI can show it
export class InspectorError extends Error {
  constructor(message, { status = 502, phase = null } = {}) {
    super(message);
    this.name = 'InspectorError';
    this.status = status;
    this.phase = phase;
  }
}
