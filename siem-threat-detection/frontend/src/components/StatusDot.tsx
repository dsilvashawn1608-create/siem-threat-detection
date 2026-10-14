type Severity = "low" | "medium" | "high" | "critical" | string;

const COLORS: Record<string, string> = {
  low: "bg-console-low",
  medium: "bg-console-med",
  high: "bg-console-high",
  critical: "bg-console-crit",
};

export function StatusDot({ severity }: { severity: Severity }) {
  const color = COLORS[severity] ?? "bg-console-dim";
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`h-2.5 w-2.5 rounded-full ${color} shrink-0`} />
      <span className="uppercase text-xs tracking-wide">{severity}</span>
    </span>
  );
}
