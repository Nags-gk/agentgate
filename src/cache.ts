/**
 * Small TTL cache with in-flight de-duplication, for data read on every tool call (user,
 * bundles, tenant settings). Policy edits take effect within POLICY_TTL_MS on every
 * instance; an edit made through this instance's admin API clears it immediately.
 */
export const POLICY_TTL_MS = 5_000;

export class TtlCache<T> {
  private map = new Map<string, { at: number; value: Promise<T> }>();
  constructor(private readonly ttlMs = POLICY_TTL_MS) {}

  get(key: string, load: () => Promise<T>): Promise<T> {
    const hit = this.map.get(key);
    if (hit && Date.now() - hit.at < this.ttlMs) return hit.value;
    const value = load();
    this.map.set(key, { at: Date.now(), value });
    value.catch(() => this.map.delete(key));
    if (this.map.size > 10_000) this.map.clear();
    return value;
  }

  clear(): void {
    this.map.clear();
  }
}

const all: Array<TtlCache<unknown>> = [];
export function cache<T>(ttlMs?: number): TtlCache<T> {
  const c = new TtlCache<T>(ttlMs);
  all.push(c as TtlCache<unknown>);
  return c;
}
/** Called after admin changes to policy, agents or settings. */
export const clearPolicyCaches = () => all.forEach((c) => c.clear());
