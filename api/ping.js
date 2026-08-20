// Temporary probe: does this project build serverless functions at all?
export default function handler(req, res) {
  res.status(200).json({ ok: true, url: req.url });
}
