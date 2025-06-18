const currentURL = "https://example.com";

  try {
    const response = await fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentURL }),
    });

    const result = await response.json();
    console.log("🛡️ SafeSearch Result:", result);
  } catch (error) {
    console.error("❌ SafeSearch API call failed:", error);
  }