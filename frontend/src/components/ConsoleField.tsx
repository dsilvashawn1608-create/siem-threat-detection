import type { ReactNode } from "react";

export function ConsoleField({
  label,
  value,
}: {
  label: string;
  value: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[10px] uppercase tracking-widest text-console-dim">
        {label}
      </span>
      <span className="text-sm text-console-text break-all">{value}</span>
    </div>
  );
}
