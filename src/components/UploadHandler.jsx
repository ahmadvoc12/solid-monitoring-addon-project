import { runViolenceDetection } from "../services/violenceDetection";

export async function handleUpload(file) {

  // proses upload normal
  console.log("File uploaded");

  // 🔗 HUBUNGKAN KE DETEKSI
  const result = await runViolenceDetection(file);

  if (result?.violence) {
    alert("Violence detected with confidence " + result.confidence);
  }
}
