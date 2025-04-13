window.addEventListener('DOMContentLoaded', () => {
  const hiddenData = hiddendata_check();
  if (hiddenData.hiddenPasswordFields) {
    alert("⚠️ Hidden password field detected!");
  }
  console.log("Hidden form data:", hiddenData);
});
