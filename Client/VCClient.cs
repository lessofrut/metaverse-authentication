// VCClient.cs
using UnityEngine;
using UnityEngine.Networking;
using System.Collections;
using System.Text;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;

public class VCClient : MonoBehaviour
{
    [SerializeField]
    private string serverUrl = "http://192.168.1.1:5000";

    private JObject currentVC;
    private JObject issuerDID;
    private JObject holderDID;

    private readonly string holderDIDId    = "did:example:holder456";
    private readonly string holderPublicKey = "holder_secret_key_for_hmac_67890";
    private readonly string issuerPublicKey = "issuer_secret_key_for_hmac_12345";

    private bool credentialsLoaded = false;

    public delegate void OnVerificationComplete(bool success, string message, JObject details);
    public event OnVerificationComplete VerificationCompleted;
    public event System.Action          OnCredentialsLoaded;
    public event System.Action<string>  OnCredentialsFailed; // nuovo — passa il messaggio di errore

    // ─── Lifecycle ─────────────────────────────────────────────────────────

    void Start()
    {
        StartCoroutine(LoadCredentialsCoroutine());
    }

    // ─── Credentials Loading ───────────────────────────────────────────────

    private IEnumerator LoadCredentialsCoroutine()
    {
        string basePath   = System.IO.Path.Combine(Application.streamingAssetsPath, "Credentials");
        string vcPath     = System.IO.Path.Combine(basePath, "holder_vc.json");
        string issuerPath = System.IO.Path.Combine(basePath, "issuer_did.json");
        string holderPath = System.IO.Path.Combine(basePath, "holder_did.json");

        Debug.Log($"[VCClient] Loading credentials from: {basePath}");

        yield return StartCoroutine(LoadJsonFile(vcPath, json =>
        {
            currentVC = JObject.Parse(json);
            Debug.Log("[VCClient] ✓ VC loaded");
        }));

        yield return StartCoroutine(LoadJsonFile(issuerPath, json =>
        {
            issuerDID = JObject.Parse(json);
            Debug.Log("[VCClient] ✓ Issuer DID loaded");
        }));

        yield return StartCoroutine(LoadJsonFile(holderPath, json =>
        {
            holderDID = JObject.Parse(json);
            Debug.Log("[VCClient] ✓ Holder DID loaded");
        }));

        // Check which files failed
        if (currentVC == null || issuerDID == null || holderDID == null)
        {
            string missing = "";
            if (currentVC  == null) missing += "\n• holder_vc.json";
            if (issuerDID  == null) missing += "\n• issuer_did.json";
            if (holderDID  == null) missing += "\n• holder_did.json";

            string errorMsg = $"Failed to load credentials:{missing}\n\nCheck that files exist in StreamingAssets/Credentials/";
            Debug.LogError($"[VCClient] ✗ {errorMsg}");
            OnCredentialsFailed?.Invoke(errorMsg);
            yield break; // ← CORRETTO
        }

        credentialsLoaded = true;
        Debug.Log("[VCClient] ✓ All credentials loaded successfully");
        OnCredentialsLoaded?.Invoke();
    }

private IEnumerator LoadJsonFile(string path, System.Action<string> onSuccess)
    {
        // On Android, Application.streamingAssetsPath already formats the path correctly for UnityWebRequest.
        // On PC/Editor, we need to add "file://" if it's not already there.
        string url = path;
        
#if !UNITY_ANDROID || UNITY_EDITOR
        if (!url.StartsWith("file://"))
        {
            url = "file://" + url;
        }
#endif

        Debug.Log($"[VCClient] Fetching: {url}");

        using (UnityWebRequest request = UnityWebRequest.Get(url))
        {
            request.timeout = 10;
            yield return request.SendWebRequest();

            if (request.result == UnityWebRequest.Result.Success)
            {
                try
                {
                    onSuccess(request.downloadHandler.text);
                }
                catch (System.Exception e)
                {
                    Debug.LogError($"[VCClient] Failed to parse {path}: {e.Message}");
                }
            }
            else
            {
                Debug.LogError($"[VCClient] Failed to fetch {url}: {request.error}");
            }
        }
    }

    // ─── Public API ────────────────────────────────────────────────────────

    public void SendVPForVerification()
    {
        if (!credentialsLoaded)
        {
            Debug.LogError("[VCClient] Credentials not loaded");
            VerificationCompleted?.Invoke(false, "Credentials not ready.", null);
            return;
        }

        StartCoroutine(VerifyVPCoroutine());
    }

    // ─── VP Creation & Sending ─────────────────────────────────────────────

    private IEnumerator VerifyVPCoroutine()
    {
        JObject vp = CreateVerifiablePresentation();

        if (vp == null)
        {
            VerificationCompleted?.Invoke(false, "Failed to create Verifiable Presentation.", null);
            yield break;
        }

        JObject payload  = new JObject { ["vp"] = vp };
        string jsonPayload = payload.ToString(Newtonsoft.Json.Formatting.None);

        Debug.Log("[VCClient] Sending VP to server...");

        using (UnityWebRequest request = new UnityWebRequest(
            $"{serverUrl}/verify-vp", UnityWebRequest.kHttpVerbPOST))
        {
            byte[] bodyRaw        = Encoding.UTF8.GetBytes(jsonPayload);
            request.uploadHandler   = new UploadHandlerRaw(bodyRaw);
            request.downloadHandler = new DownloadHandlerBuffer();
            request.SetRequestHeader("Content-Type", "application/json");
            request.timeout = 30;

            yield return request.SendWebRequest();

            if (request.result == UnityWebRequest.Result.Success)
                HandleVerificationResponse(request.downloadHandler.text);
            else
                HandleVerificationError(request.error);
        }
    }

    private JObject CreateVerifiablePresentation()
    {
        try
        {
            JObject vcClone = (JObject)currentVC.DeepClone();
            SignVC(vcClone);

            JObject vp = new JObject
            {
                ["@context"]             = "https://www.w3.org/2018/credentials/v1",
                ["type"]                 = "VerifiablePresentation",
                ["verifiableCredential"] = new JArray(vcClone),
                ["holder"]               = holderDIDId
            };

            JObject vpForSigning = (JObject)vp.DeepClone();
            vpForSigning.Remove("proof");

            string vpMessage   = vpForSigning.ToString(Newtonsoft.Json.Formatting.None);
            string vpSignature = GenerateSignature(vpMessage, holderPublicKey);

            vp["proof"] = new JObject
            {
                ["type"]           = "HMACSHA256Signature2020",
                ["created"]        = System.DateTime.UtcNow.ToString("o"),
                ["signatureValue"] = vpSignature
            };

            Debug.Log("[VCClient] ✓ VP created successfully");
            return vp;
        }
        catch (System.Exception e)
        {
            Debug.LogError($"[VCClient] Failed to create VP: {e.Message}\n{e.StackTrace}");
            return null;
        }
    }

    private void SignVC(JObject vc)
    {
        try
        {
            if (vc.ContainsKey("proof"))
            {
                string sig = vc["proof"]?["signatureValue"]?.ToString();
                if (!string.IsNullOrEmpty(sig) && sig != "placeholder_vc_signature")
                {
                    Debug.Log("[VCClient] VC already signed, skipping");
                    return;
                }
            }

            JObject vcForSigning = (JObject)vc.DeepClone();
            vcForSigning.Remove("proof");

            string vcMessage   = vcForSigning.ToString(Newtonsoft.Json.Formatting.None);
            string vcSignature = GenerateSignature(vcMessage, issuerPublicKey);

            vc["proof"] = new JObject
            {
                ["type"]           = "HMACSHA256Signature2020",
                ["created"]        = System.DateTime.UtcNow.ToString("o"),
                ["signatureValue"] = vcSignature
            };

            Debug.Log("[VCClient] ✓ VC signed successfully");
        }
        catch (System.Exception e)
        {
            Debug.LogError($"[VCClient] Failed to sign VC: {e.Message}\n{e.StackTrace}");
        }
    }

    private string GenerateSignature(string message, string key)
    {
        using (HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
        {
            byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
            return System.BitConverter.ToString(hash).Replace("-", "").ToLower();
        }
    }

    // ─── Response Handling ─────────────────────────────────────────────────

    private void HandleVerificationResponse(string response)
    {
        Debug.Log($"[VCClient] Server response: {response}");
        try
        {
            JObject result = JObject.Parse(response);
            bool    success = result["success"]?.Value<bool>()   ?? false;
            string  message = result["details"]?.Value<string>() ?? "No details provided";
            VerificationCompleted?.Invoke(success, message, result);
        }
        catch (System.Exception e)
        {
            Debug.LogError($"[VCClient] Failed to parse response: {e.Message}");
            VerificationCompleted?.Invoke(false, $"Failed to parse server response: {e.Message}", null);
        }
    }

    private void HandleVerificationError(string error)
    {
        Debug.LogError($"[VCClient] Request failed: {error}");
        VerificationCompleted?.Invoke(false, $"Server unreachable: {error}", null);
    }
}