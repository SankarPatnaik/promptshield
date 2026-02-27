export const metadata = {
  title: "PromptShield",
  description: "Prompt validation + injection defense + local shield scoring"
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ margin: 0 }}>{children}</body>
    </html>
  );
}
