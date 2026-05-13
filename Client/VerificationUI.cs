// VerificationUI.cs
using UnityEngine;
using TMPro;
using UnityEngine.UI;
using Newtonsoft.Json.Linq;

public class VerificationUI : MonoBehaviour
{
    [SerializeField] private TextMeshProUGUI titleText;
    [SerializeField] private TextMeshProUGUI statusText;
    [SerializeField] private TextMeshProUGUI detailsText;
    [SerializeField] private TextMeshProUGUI checksText;
    [SerializeField] private Button          verifyButton;
    [SerializeField] private Button          retryButton;
    [SerializeField] private Image           panelImage;

    private VCClient vcClient;
    private bool     isVerifying = false;

    // ─── Lifecycle ─────────────────────────────────────────────────────────

    void Start()
    {
        vcClient = GetComponent<VCClient>();
        if (vcClient == null)
        {
            Debug.LogError("[VerificationUI] VCClient not found on this GameObject!");
            return;
        }

        // Subscribe to all VCClient events
        vcClient.VerificationCompleted += OnVerificationCompleted;
        vcClient.OnCredentialsLoaded   += OnCredentialsReady;
        vcClient.OnCredentialsFailed   += OnCredentialsError;

        // Wire buttons
        if (verifyButton != null)
            verifyButton.onClick.AddListener(OnVerifyClicked);
        else
            Debug.LogError("[VerificationUI] verifyButton is not assigned!");

        if (retryButton != null)
            retryButton.onClick.AddListener(OnRetryClicked);
        else
            Debug.LogError("[VerificationUI] retryButton is not assigned!");

        ShowLoadingState();
    }

    private void OnDestroy()
    {
        if (vcClient != null)
        {
            vcClient.VerificationCompleted -= OnVerificationCompleted;
            vcClient.OnCredentialsLoaded   -= OnCredentialsReady;
            vcClient.OnCredentialsFailed   -= OnCredentialsError;
        }

        if (verifyButton != null) verifyButton.onClick.RemoveListener(OnVerifyClicked);
        if (retryButton  != null) retryButton.onClick.RemoveListener(OnRetryClicked);
    }

    // ─── UI States ─────────────────────────────────────────────────────────

    private void ShowLoadingState()
    {
        SetText(titleText,   "Verify Your Credentials");
        SetText(statusText,  "Loading credentials...");
        SetText(detailsText, "Please wait...");
        SetText(checksText,  "");

        SetStatusColor(Color.yellow);
        SetPanelColor(new Color(0.15f, 0.15f, 0.15f, 0.9f));

        SetButtonState(verifyButton, active: true,  interactable: false);
        SetButtonState(retryButton,  active: false, interactable: false);
    }

    private void ShowReadyState()
    {
        SetText(statusText,  "Ready");
        SetText(detailsText, "Click 'Verify VC' to authenticate your credentials");
        SetText(checksText,  "");

        SetStatusColor(Color.white);
        SetPanelColor(new Color(0.15f, 0.15f, 0.15f, 0.9f));

        SetButtonState(verifyButton, active: true,  interactable: true);
        SetButtonState(retryButton,  active: false, interactable: false);
    }

    private void ShowVerifyingState()
    {
        SetText(statusText,  "Verifying...");
        SetText(detailsText, "Sending credentials to server...");
        SetText(checksText,  "");

        SetStatusColor(Color.yellow);

        SetButtonState(verifyButton, active: true,  interactable: false);
        SetButtonState(retryButton,  active: false, interactable: false);
    }

    private void ShowResultState(bool success, string message, JObject details)
    {
        SetText(statusText,  success ? "✓ Verification Successful!" : "✗ Verification Failed");
        SetText(detailsText, message);
        SetText(checksText,  details != null ? BuildChecksInfo(details) : "");

        SetStatusColor(success ? Color.green : Color.red);
        SetPanelColor(success
            ? new Color(0f,   0.3f, 0f,   0.9f)
            : new Color(0.3f, 0f,   0f,   0.9f));

        SetButtonState(verifyButton, active: false, interactable: false);
        SetButtonState(retryButton,  active: true,  interactable: true);
    }

    private void ShowErrorState(string errorMessage)
    {
        SetText(titleText,   "Credentials Error");
        SetText(statusText,  "✗ Failed to load credentials");
        SetText(detailsText, errorMessage);
        SetText(checksText,  "");

        SetStatusColor(Color.red);
        SetPanelColor(new Color(0.3f, 0f, 0f, 0.9f));

        // Both buttons disabled — nothing the user can do without fixing the files
        SetButtonState(verifyButton, active: false, interactable: false);
        SetButtonState(retryButton,  active: false, interactable: false);
    }

    // ─── VCClient Event Handlers ───────────────────────────────────────────

    private void OnCredentialsReady()
    {
        Debug.Log("[VerificationUI] Credentials ready");
        ShowReadyState();
    }

    private void OnCredentialsError(string errorMessage)
    {
        Debug.LogError($"[VerificationUI] Credentials failed: {errorMessage}");
        ShowErrorState(errorMessage);
    }

    private void OnVerificationCompleted(bool success, string message, JObject details)
    {
        isVerifying = false;
        ShowResultState(success, message, details);

        if (success)
        {
            Debug.Log("[VerificationUI] Verification successful, loading MainGame in 3s...");
            Invoke(nameof(LoadMainScene), 3f);
        }
    }

    // ─── Button Callbacks ──────────────────────────────────────────────────

    private void OnVerifyClicked()
    {
        if (isVerifying) return;
        isVerifying = true;

        ShowVerifyingState();
        Debug.Log("[VerificationUI] Verify button clicked");
        vcClient.SendVPForVerification();
    }

    private void OnRetryClicked()
    {
        isVerifying = false;
        ShowReadyState();
        Debug.Log("[VerificationUI] Retry button clicked");
    }

    // ─── Helpers ───────────────────────────────────────────────────────────

    private string BuildChecksInfo(JObject result)
    {
        try
        {
            var checks = result["checks"];
            if (checks == null) return "";

            var sb = new System.Text.StringBuilder("Verification Checks:\n");
            foreach (JProperty check in checks)
            {
                bool   passed = check.Value.Value<bool>();
                string symbol = passed ? "✓" : "✗";
                sb.AppendLine($"{symbol} {check.Name}");
            }
            return sb.ToString();
        }
        catch (System.Exception e)
        {
            Debug.LogWarning($"[VerificationUI] Failed to parse checks: {e.Message}");
            return "";
        }
    }

    private void SetText(TextMeshProUGUI tmp, string text)
    {
        if (tmp != null) tmp.text = text;
    }

    private void SetStatusColor(Color color)
    {
        if (statusText != null) statusText.color = color;
    }

    private void SetPanelColor(Color color)
    {
        if (panelImage != null) panelImage.color = color;
    }

    private void SetButtonState(Button btn, bool active, bool interactable)
    {
        if (btn == null) return;
        btn.gameObject.SetActive(active);
        btn.interactable = interactable;
    }

    private void LoadMainScene()
    {
        Debug.Log("[VerificationUI] Loading MainGame scene...");
        UnityEngine.SceneManagement.SceneManager.LoadScene("MainGame");
    }
}
