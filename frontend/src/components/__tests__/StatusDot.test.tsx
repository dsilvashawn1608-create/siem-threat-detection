import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { StatusDot } from "../StatusDot";

describe("StatusDot", () => {
  it("renders the severity label in uppercase", () => {
    render(<StatusDot severity="high" />);
    expect(screen.getByText("high")).toBeInTheDocument();
  });

  it.each([
    ["low", "bg-console-low"],
    ["medium", "bg-console-med"],
    ["high", "bg-console-high"],
    ["critical", "bg-console-crit"],
  ])("maps severity %s to its color class", (severity, expectedClass) => {
    const { container } = render(<StatusDot severity={severity} />);
    const dot = container.querySelector("span.rounded-full");
    expect(dot).toHaveClass(expectedClass);
  });

  it("falls back to the dim color for an unrecognized severity", () => {
    const { container } = render(<StatusDot severity="unknown-thing" />);
    const dot = container.querySelector("span.rounded-full");
    expect(dot).toHaveClass("bg-console-dim");
  });
});
