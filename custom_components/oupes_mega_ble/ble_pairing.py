"""BLE pairing for OUPES Mega - programs a new device_key over Bluetooth.

Replicates the exact Cleanergy app pairing protocol (reverse-engineered from
a bugreport btsnoop HCI capture):

    AUTH (11 pkts) -> 0x03 handshake polling -> re-AUTH -> more polling ->
    CLAIM data (10 pkts with key + dummy MQTT token) -> wait for confirmation

The device must be in pairing mode (5 s IoT button hold -> rapid flash).
"""
from __future__ import annotations

import asyncio
import logging
import secrets
import struct
import string
import time
from enum import Enum

from bleak import BleakClient
from bleak_retry_connector import establish_connection

from homeassistant.components.bluetooth import async_ble_device_from_address
from homeassistant.core import HomeAssistant

from .protocol import (
    WRITE_CHAR_UUID,
    NOTIFY_CHAR_UUID,
    _crc8,
    build_config_net_packets,
    build_init_sequence,
)

_LOGGER = logging.getLogger(__name__)

# Dummy MQTT token (30 chars, alphanumeric).  The device stores this for cloud
# use; for BLE-only / HA-only setups it is irrelevant, but the claim packet
# format requires it.
_DUMMY_TOKEN = b"HALOCAL000000000000000000000000"[:30]


class PairingResult(Enum):
    """Outcome of a BLE pairing attempt."""

    SUCCESS = "success"
    DEVICE_NOT_FOUND = "device_not_found"
    CONNECTION_FAILED = "connection_failed"
    TIMEOUT = "timeout"
    INVALID_CREDENTIALS = "invalid_credentials"
    WIFI_DEVICE_NOT_FOUND = "wifi_device_not_found"
    WIFI_CONNECTION_FAILED = "wifi_connection_failed"
    WIFI_TIMEOUT = "wifi_timeout"


def _ts_pkt(prefix: int) -> bytes:
    """Build a timestamp handshake packet."""
    now = int(time.time())
    p = bytearray(20)
    p[0] = prefix
    p[1] = 0x80
    p[2] = 0x00
    p[3] = 0x04
    p[4:8] = struct.pack("<I", now)
    p[19] = _crc8(bytes(p[:19]))
    return bytes(p)


def _build_claim(key: str, token: bytes = _DUMMY_TOKEN) -> list[bytes]:
    """Build the 0x03 CLAIM data sequence (10 packets)."""
    kb = key.encode("ascii").ljust(10, b"\x00")[:10]
    tok = token.ljust(30, b"\x00")[:30]
    full = kb + tok  # 40 bytes

    def _raw(cmd: int, data: bytes) -> bytes:
        p = bytearray(20)
        p[0] = 0x03
        p[1] = cmd
        d = data.ljust(17, b"\x00")[:17]
        p[2 : 2 + len(d)] = d
        p[19] = _crc8(bytes(p[:19]))
        return bytes(p)

    return [
        bytes.fromhex("03000199020202020202020202020202020202b8"),
        bytes.fromhex("03010202020202020202020202020202020202b1"),
        _raw(0x02, b""),
        _raw(0x03, b""),
        _raw(0x04, b""),
        _raw(0x05, b""),
        _raw(0x06, b"\x00\x00" + full[0:15]),
        _raw(0x07, full[15:32]),
        _raw(0x08, full[32:]),
        _raw(0x89, b""),
    ]


async def async_pair_device(
    hass: HomeAssistant,
    address: str,
    device_key: str,
    max_cycles: int = 4,
    progress_callback=None,
    ssid: str = "",
    psk: str = "",
    bssid: str = "",
    region: str = "wp-cn",
) -> PairingResult:
    """Run the full BLE pairing flow for an OUPES Mega device.

    Args:
        hass: Home Assistant instance (needed for HA's Bluetooth stack).
        address: Bluetooth MAC address (e.g. "8C:D0:B2:A8:E1:44").
        device_key: 10-character hex key to program.
        max_cycles: Maximum reconnect cycles to attempt.
        progress_callback: Optional async callable(msg: str) for UI updates.

    Returns:
        PairingResult indicating outcome.
    """

    async def _report(msg: str) -> None:
        _LOGGER.debug("BLE pairing: %s", msg)
        if progress_callback:
            try:
                await progress_callback(msg)
            except Exception:  # noqa: BLE001
                pass

    for cycle in range(1, max_cycles + 1):
        await _report(f"Cycle {cycle}/{max_cycles}: looking for device...")

        # Use HA's Bluetooth stack to find the device - this respects
        # adapter selection and avoids raw BleakScanner issues.
        ble_device = async_ble_device_from_address(
            hass, address, connectable=True
        )
        if ble_device is None:
            if cycle == 1:
                # First cycle: also try a short wait in case HA hasn't
                # cached the advertisement yet.
                await asyncio.sleep(5)
                ble_device = async_ble_device_from_address(
                    hass, address, connectable=True
                )
            if ble_device is None:
                if cycle >= max_cycles:
                    return PairingResult.DEVICE_NOT_FOUND
                await _report(f"Device not seen yet, waiting to retry...")
                await asyncio.sleep(5)
                continue

        await _report(f"Cycle {cycle}/{max_cycles}: connecting...")

        result = await _pairing_cycle(
            ble_device,
            device_key,
            _report,
            region=region,
        )
        if result == PairingResult.SUCCESS:
            if ssid:
                await _report("Pairing complete; configuring Wi-Fi...")
                wifi_result = await async_provision_wifi(
                    hass, address, device_key, ssid, psk, bssid
                )
                if wifi_result != PairingResult.SUCCESS:
                    return {
                        PairingResult.DEVICE_NOT_FOUND: PairingResult.WIFI_DEVICE_NOT_FOUND,
                        PairingResult.CONNECTION_FAILED: PairingResult.WIFI_CONNECTION_FAILED,
                        PairingResult.INVALID_CREDENTIALS: PairingResult.INVALID_CREDENTIALS,
                    }.get(wifi_result, PairingResult.WIFI_TIMEOUT)
            return result

        if cycle < max_cycles:
            await _report(f"Cycle {cycle} did not confirm - retrying...")
            await asyncio.sleep(3)

    return PairingResult.TIMEOUT


async def _pairing_cycle(
    dev,
    key: str,
    report,
    region: str = "wp-cn",
) -> PairingResult:
    """Execute one full pairing cycle on a single BLE connection."""

    claim_accepted = False
    auth_configured = False
    got_telemetry = False

    def on_notify(_h, data: bytearray):
        nonlocal claim_accepted, auth_configured, got_telemetry
        pkt = bytes(data)
        if len(pkt) < 5:
            return
        prefix = pkt[0]
        if prefix == 0x03 and pkt[1] == 0x80 and pkt[2] == 0x01 and pkt[4] == 0x00:
            claim_accepted = True
        elif prefix == 0x01 and pkt[1] == 0x80 and pkt[2] == 0x01 and pkt[4] == 0x00:
            auth_configured = True
        elif prefix == 0x01 and pkt[1] in (0x00, 0x81) and len(pkt) >= 3 and pkt[2] == 0x0A:
            got_telemetry = True

    try:
        client = await establish_connection(
            client_class=BleakClient,
            device=dev,
            name=str(dev.address if hasattr(dev, 'address') else dev),
        )
    except Exception as exc:
        _LOGGER.debug("BLE pairing connection error: %s", exc)
        return PairingResult.CONNECTION_FAILED

    try:
        await client.start_notify(NOTIFY_CHAR_UUID, on_notify)
        await asyncio.sleep(1.5)

        # Step 1: AUTH
        auth_seq = build_init_sequence(key, region=region)
        for pkt in auth_seq:
            await client.write_gatt_char(WRITE_CHAR_UUID, pkt, response=False)
            await asyncio.sleep(0.08)
        await asyncio.sleep(1.0)

        # Step 2: 0x03 handshake polling (~5s)
        await report("Handshake polling...")
        for _ in range(17):
            await client.write_gatt_char(
                WRITE_CHAR_UUID, _ts_pkt(0x03), response=False
            )
            await asyncio.sleep(0.3)
            if claim_accepted or auth_configured:
                break

        # Step 3: timestamp + re-AUTH
        await client.write_gatt_char(
            WRITE_CHAR_UUID, _ts_pkt(0x01), response=False
        )
        await asyncio.sleep(0.05)
        for pkt in auth_seq:
            await client.write_gatt_char(WRITE_CHAR_UUID, pkt, response=False)
            await asyncio.sleep(0.08)

        # Step 4: more 0x03 handshake polling
        for _ in range(17):
            await client.write_gatt_char(
                WRITE_CHAR_UUID, _ts_pkt(0x03), response=False
            )
            await asyncio.sleep(0.3)
            if claim_accepted or auth_configured:
                break

        # Step 5: CLAIM data
        await report("Sending claim data...")
        claim_seq = _build_claim(key)
        for pkt in claim_seq:
            await client.write_gatt_char(WRITE_CHAR_UUID, pkt, response=False)
            await asyncio.sleep(0.05)

        # Step 6: keepalive + wait for confirmation
        keepalive = bytes.fromhex(
            "0180030254010000000000000000000000000076"
        )
        await client.write_gatt_char(WRITE_CHAR_UUID, keepalive, response=False)
        await asyncio.sleep(5.0)

        if not (claim_accepted or auth_configured or got_telemetry):
            await client.write_gatt_char(
                WRITE_CHAR_UUID, keepalive, response=False
            )
            await asyncio.sleep(5.0)

        # Step 7: final AUTH verification
        if not auth_configured and not got_telemetry:
            await client.write_gatt_char(
                WRITE_CHAR_UUID, _ts_pkt(0x01), response=False
            )
            await asyncio.sleep(0.05)
            for pkt in auth_seq:
                await client.write_gatt_char(
                    WRITE_CHAR_UUID, pkt, response=False
                )
                await asyncio.sleep(0.08)
            await asyncio.sleep(5.0)

        try:
            await client.stop_notify(NOTIFY_CHAR_UUID)
        except Exception:  # noqa: BLE001
            pass

    except Exception as exc:
        _LOGGER.debug("BLE pairing connection error: %s", exc)
        return PairingResult.CONNECTION_FAILED
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass

    if claim_accepted or auth_configured or got_telemetry:
        return PairingResult.SUCCESS
    return PairingResult.TIMEOUT


async def async_provision_wifi(
    hass: HomeAssistant,
    address: str,
    device_key: str,
    ssid: str,
    psk: str,
    bssid: str = "",
) -> PairingResult:
    """Send new WiFi credentials to an already-paired OUPES device over BLE.

    Unlike async_pair_device, this does NOT factory-reset or re-key the device.
    It sends the config-net bind and credentials commands, then waits for the
    device's CMD12 join status.
    """
    open_id = "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(30)
    )
    try:
        bind_packets = build_config_net_packets("", "", device_key, open_id)
        credential_packets = build_config_net_packets(
            ssid, psk, device_key, open_id, bssid
        )
    except (UnicodeError, ValueError):
        return PairingResult.INVALID_CREDENTIALS

    _LOGGER.info(
        "Wi-Fi config-net request for %s: target SSID=%r, BSSID=%s",
        address,
        ssid,
        bssid or "unspecified",
    )

    ble_device = async_ble_device_from_address(hass, address, connectable=True)
    if ble_device is None:
        await asyncio.sleep(5)
        ble_device = async_ble_device_from_address(hass, address, connectable=True)
    if ble_device is None:
        return PairingResult.DEVICE_NOT_FOUND

    cmd12_status = None
    saw_cmd11 = False

    def on_notify(_h, data: bytearray):
        nonlocal cmd12_status, saw_cmd11
        pkt = bytes(data)
        if len(pkt) < 5:
            return
        if pkt[2] == 0x0C:
            cmd12_status = pkt[4]
        elif pkt[2] == 0x0B:
            saw_cmd11 = True

    try:
        client = await establish_connection(
            client_class=BleakClient,
            device=ble_device,
            name=str(ble_device.address),
        )
    except Exception:
        _LOGGER.debug("WiFi provision: connection failed to %s", address)
        return PairingResult.CONNECTION_FAILED

    try:
        await client.start_notify(NOTIFY_CHAR_UUID, on_notify)
        await asyncio.sleep(1.5)

        async def _send_packets(packets: list[bytes]) -> None:
            for packet in packets:
                await client.write_gatt_char(
                    WRITE_CHAR_UUID, packet, response=False
                )
                await asyncio.sleep(0.08)

        await _send_packets(bind_packets)
        await asyncio.sleep(1.0)
        cmd12_status = None
        await _send_packets(credential_packets)

        keepalive = bytes.fromhex(
            "0180030254010000000000000000000000000076"
        )
        for interval in range(120):
            await asyncio.sleep(0.5)
            if cmd12_status is not None:
                break
            if interval % 20 == 0:
                await client.write_gatt_char(
                    WRITE_CHAR_UUID, keepalive, response=False
                )

        if cmd12_status in (0x00, 0x01):
            _LOGGER.info(
                "Wi-Fi config-net result for %s: device reported joined "
                "(CMD12=0x%02x) for requested SSID=%r; SSID is not echoed",
                address,
                cmd12_status,
                ssid,
            )
        elif cmd12_status is None:
            _LOGGER.warning(
                "Wi-Fi config-net result for %s: no CMD12 join confirmation "
                "for requested SSID=%r (CMD11 observed=%s)",
                address,
                ssid,
                saw_cmd11,
            )
        else:
            _LOGGER.warning(
                "Wi-Fi config-net result for %s: device returned CMD12=0x%02x "
                "for requested SSID=%r (not a success code)",
                address,
                cmd12_status,
                ssid,
            )

        try:
            await client.stop_notify(NOTIFY_CHAR_UUID)
        except Exception:  # noqa: BLE001
            pass
    except Exception as exc:
        _LOGGER.debug("WiFi provision error: %s", exc)
        return PairingResult.CONNECTION_FAILED
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass

    if cmd12_status in (0x00, 0x01):
        return PairingResult.SUCCESS
    return PairingResult.TIMEOUT

