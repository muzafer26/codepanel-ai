export const metadata = {
  title: "CodePanel AI — 3-Agent Code Review",
  description: "AI-powered code review with 3 specialist agents and a meta-reviewer",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, padding: 0 }}>{children}</body>
    </html>
  );
}
