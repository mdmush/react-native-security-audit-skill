// "Ask the sommelier" feature: suggests a wine pairing for the current order.
const API_KEY = process.env.EXPO_PUBLIC_OPENAI_API_KEY;

export async function suggestPairing(dishes: string[]): Promise<string> {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${API_KEY}` },
    body: JSON.stringify({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: `Suggest a wine pairing for: ${dishes.join(', ')}` }],
    }),
  });
  const json = await res.json();
  return json.choices[0].message.content;
}
