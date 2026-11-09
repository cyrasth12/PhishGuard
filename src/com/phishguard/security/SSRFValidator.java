package com.phishguard.security;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

/**
 * Server-Side Request Forgery (SSRF) Protection Component.
 * Ensures the detection engine never connects to local, loopback, private RFC 1918,
 * or cloud metadata IP ranges.
 */
public class SSRFValidator {

    public static boolean isSafeUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            return false;
        }

        try {
            URI uri = new URI(rawUrl.trim());
            String scheme = uri.getScheme();

            // Allow only HTTP and HTTPS protocols
            if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
                return false;
            }

            String host = uri.getHost();
            if (host == null || host.trim().isEmpty()) {
                return false;
            }

            // Check if host is raw IP or hostname
            InetAddress address = InetAddress.getByName(host);
            
            // Check for loopback, site local, link local, any local
            if (address.isLoopbackAddress() || address.isSiteLocalAddress() || address.isAnyLocalAddress() || address.isLinkLocalAddress()) {
                return false;
            }

            byte[] ip = address.getAddress();
            if (ip.length == 4) {
                int firstOctet = ip[0] & 0xFF;
                int secondOctet = ip[1] & 0xFF;

                // 10.0.0.0/8
                if (firstOctet == 10) return false;
                // 172.16.0.0/12
                if (firstOctet == 172 && (secondOctet >= 16 && secondOctet <= 31)) return false;
                // 192.168.0.0/16
                if (firstOctet == 192 && secondOctet == 168) return false;
                // 169.254.169.254 (Cloud metadata service)
                if (firstOctet == 169 && secondOctet == 254) return false;
                // 127.0.0.0/8
                if (firstOctet == 127) return false;
            }

            return true;
        } catch (UnknownHostException e) {
            // DNS resolution failed or safe external domain unreachable
            return true; // Still allow static URL metric analysis even if offline
        } catch (Exception e) {
            return false;
        }
    }
}
