package vault.agent;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/** Gọi Vault server thay mặt admin (dùng token admin mà web gửi kèm). */
public class ServerClient {
    private final String baseUrl;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    public ServerClient(String baseUrl) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
    }

    public Map<String, Object> post(String path, String bearer, Map<String, Object> body) {
        if (bearer == null || bearer.isBlank()) {
            throw new AgentException(401, "NO_TOKEN", "Thiếu token admin (Authorization: Bearer ...)");
        }
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(Duration.ofSeconds(15))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + bearer)
                .POST(HttpRequest.BodyPublishers.ofString(Json.write(body), StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> resp;
        try {
            resp = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new AgentException(502, "SERVER_UNREACHABLE", "Không gọi được Vault server " + baseUrl + ": " + e.getMessage());
        }
        Map<String, Object> json;
        try {
            json = Json.parseObject(resp.body());
        } catch (RuntimeException e) {
            throw new AgentException(502, "SERVER_BAD_RESPONSE", "Server trả dữ liệu không phải JSON (HTTP " + resp.statusCode() + ")");
        }
        if (resp.statusCode() >= 400) {
            Object msg = json.get("error");
            throw new AgentException(resp.statusCode(), String.valueOf(json.getOrDefault("code", "SERVER_ERROR")),
                    "Server: " + (msg != null ? msg : "HTTP " + resp.statusCode()));
        }
        return json;
    }
}
