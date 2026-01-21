#!/bin/bash
# =============================================================================
# VPN Routing Setup (Open Source)
# =============================================================================
# MIT License - Full source code
# Enterprise support: grant@abejar.net
# =============================================================================

set -e

# Configuration
VPN_INTERFACE="${VPN_INTERFACE:-wg0}"
DOCKER_NETWORK="${VPN_NETWORK_CIDR:-172.25.0.0/16}"
DOCKER_GATEWAY="${VPN_NETWORK_GATEWAY:-172.25.0.1}"
VPN_ROUTER_IP="${VPN_ROUTER_IP:-172.25.0.2}"

echo "Setting up VPN routing..."

# Preserve Docker network routes
setup_docker_routes() {
    echo "Configuring Docker network preservation..."
    
    # Add route to Docker network via eth0
    ip route add "$DOCKER_NETWORK" via "$DOCKER_GATEWAY" dev eth0 table 51820 2>/dev/null || true
    ip route add "$DOCKER_NETWORK" via "$DOCKER_GATEWAY" dev eth0 2>/dev/null || true
    
    # Add rule to route traffic from VPN router through main table
    ip rule add from "$VPN_ROUTER_IP" lookup main priority 100 2>/dev/null || true
    
    echo "Docker routes configured"
}

# Setup iptables marks for return traffic
setup_marks() {
    echo "Configuring traffic marks..."
    
    # Try nftables first, fall back to iptables
    if command -v nft &> /dev/null; then
        nft add rule ip filter INPUT iif eth0 ct state new counter mark set 0xca6c 2>/dev/null || true
        nft add rule ip filter OUTPUT ct mark 0xca6c counter mark set 0xca6c 2>/dev/null || true
    else
        iptables -t mangle -A INPUT -i eth0 -m conntrack --ctstate NEW -j MARK --set-mark 0xca6c 2>/dev/null || true
        iptables -t mangle -A OUTPUT -m connmark --mark 0xca6c -j MARK --set-mark 0xca6c 2>/dev/null || true
    fi
    
    echo "Traffic marks configured"
}

# Enable IP forwarding
enable_forwarding() {
    echo "Enabling IP forwarding..."
    
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null 2>&1 || true
    
    echo "IP forwarding enabled"
}

# Main
main() {
    enable_forwarding
    setup_docker_routes
    setup_marks
    
    echo "VPN routing setup complete"
}

main "$@"
