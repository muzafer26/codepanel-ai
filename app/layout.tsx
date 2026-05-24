import { Metadata } from "next";

export const metadata: Metadata = {
  title: "⌬ CODEPANEL // AI — Enterprise Code Security & Compliance Scanner",
  description: "AI-Powered Code Security, Review & Compliance Telemetry Platform. Client-side static analysis rules meets multi-agent synthesis orchestration.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body style={{ margin: 0, padding: 0, backgroundColor: "#000000" }}>{children}</body>
    </html>
  );
}
