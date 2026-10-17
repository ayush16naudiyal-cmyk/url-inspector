import app from './app.js';

// Render (and most hosts) tell us which port to use through the PORT env var.
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`URL Inspector running at http://localhost:${PORT}`);
});
