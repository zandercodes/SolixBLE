"""F3000 power station model.

.. moduleauthor:: Harvey Lelliott (flip-dots) <harveylelliott@duck.com>

"""

import logging

from ..const import DEFAULT_METADATA_INT, DEFAULT_METADATA_STRING
from ..device import SolixBLEDevice
from ..states import PortStatus

_LOGGER = logging.getLogger(__name__)


class F3000(SolixBLEDevice):
    """
    F3000 Power Station.

    Use this class to connect and monitor a F3000 power station.
    This model is also known as the A1782.

    The F3000 is a 3072Wh portable power station with LiFePO4 batteries,
    3600W inverter output, dual MPPT solar input (up to 2400W), and
    expandable capacity with BP3000 expansion batteries.

    The F3000 uses the c421 single-packet telemetry format with compound
    TLV tags where each tag contains multiple byte-indexed sub-fields,
    as described in the ``_A1782_0421`` mapping from thomluther/anker-solix-api.

    """

    _EXPECTED_TELEMETRY_LENGTH: int = 253
    _TELEMETRY_CMDS: frozenset[str] = frozenset({"c402", "4300", "c421"})

    async def _process_telemetry_packet(self, payload: bytes) -> None:
        """
        Process a telemetry packet from an F3000 device.

        The F3000 sends telemetry as a single encrypted packet using
        command ``c421`` with leading metadata bytes that must be
        stripped before decryption.
        """
        # Single-packet telemetry (c421): strip metadata alignment bytes
        remainder = len(payload) % 16
        if remainder != 0:
            _LOGGER.debug(
                f"Stripping {remainder} leading metadata byte(s) "
                f"to align telemetry payload: {payload[:remainder].hex()}"
            )
            payload = payload[remainder:]

        decrypted_payload = self._decrypt_payload(payload)
        _LOGGER.debug(f"Decrypted payload: {decrypted_payload.hex()}")
        parameters = self._parse_payload(decrypted_payload)
        return await self._process_telemetry(parameters)

    # --- c421 compound tag properties ---
    # Tag data layout: [type_byte][field_data_bytes...]
    # MQTT field offset X maps to data[X + 1] (type byte at data[0]).

    @property
    def serial_number(self) -> str:
        """Device serial number.

        Stored as a length-prefixed string at byte offset 1 inside
        the compound ``a2`` tag (field data byte 2 = length prefix,
        bytes 3..3+length = ASCII string).

        :returns: Device serial number or default str value.
        """
        if self._data is None or "a2" not in self._data:
            return DEFAULT_METADATA_STRING
        try:
            sn_len = self._data["a2"][2]
            return self._data["a2"][3 : 3 + sn_len].decode("ascii")
        except (IndexError, UnicodeDecodeError):
            return DEFAULT_METADATA_STRING

    @property
    def temperature(self) -> int:
        """Temperature of the unit (C).

        Tag ``a5``, MQTT offset 00 → data[1], 1-byte signed.

        :returns: Temperature of the unit in degrees C.
        """
        return self._parse_int("a5", begin=1, end=2, signed=True)

    @property
    def battery_percentage(self) -> int:
        """Battery Percentage.

        Tag ``a5``, MQTT offset 02 → data[3], 1-byte unsigned.

        :returns: Percentage charge of battery or default int value.
        """
        return self._parse_int("a5", begin=3, end=4)

    @property
    def battery_percentage_aggregate(self) -> int:
        """Battery Percentage average across all batteries.

        In c421 telemetry only the main battery SOC is available.

        :returns: Percentage charge of battery or default int value.
        """
        return self.battery_percentage

    @property
    def power_out(self) -> int:
        """Total Power Out (AC + DC).

        Tag ``a6``, MQTT offset 00 → data[1:3], 2-byte signed LE.

        :returns: Total power out or default int value.
        """
        return self._parse_int("a6", begin=1, end=3)

    @property
    def ac_power_in(self) -> int:
        """AC Power In.

        Tag ``a6``, MQTT offset 02 → data[3:5], 2-byte signed LE.

        :returns: Total AC power in or default int value.
        """
        return self._parse_int("a6", begin=3, end=5)

    @property
    def ac_output(self) -> PortStatus:
        """AC Port Status.

        Tag ``a7``, MQTT offset 00 → data[1], 1-byte unsigned.
        PortStatus.NOT_CONNECTED signifies off.
        PortStatus.OUTPUT signifies on.

        :returns: Status of the AC port.
        """
        return PortStatus(self._parse_int("a7", begin=1, end=2))

    @property
    def ac_power_out(self) -> int:
        """AC Power Out.

        Tag ``a7``, MQTT offset 01 → data[2:4], 2-byte signed LE.

        :returns: Total AC power out or default int value.
        """
        return self._parse_int("a7", begin=2, end=4)

    @property
    def dc_output(self) -> PortStatus:
        """DC Port Status.

        Tag ``a8``, MQTT offset 00 → data[1], 1-byte unsigned.

        :returns: Status of the DC port.
        """
        return PortStatus(self._parse_int("a8", begin=1, end=2))

    @property
    def usb_port_c1(self) -> PortStatus:
        """USB C1 Port Status.

        Tag ``aa``, MQTT offset 00 → data[1], 1-byte unsigned.

        :returns: Status of the USB C1 port.
        """
        return PortStatus(self._parse_int("aa", begin=1, end=2))

    @property
    def usb_c1_power(self) -> int:
        """USB C1 Power.

        Tag ``aa``, MQTT offset 01 → data[2:4], 2-byte unsigned LE.

        :returns: USB port C1 power or default int value.
        """
        return self._parse_int("aa", begin=2)

    @property
    def usb_port_c2(self) -> PortStatus:
        """USB C2 Port Status.

        Tag ``ab``, MQTT offset 00 → data[1], 1-byte unsigned.

        :returns: Status of the USB C2 port.
        """
        return PortStatus(self._parse_int("ab", begin=1, end=2))

    @property
    def usb_c2_power(self) -> int:
        """USB C2 Power.

        Tag ``ab``, MQTT offset 01 → data[2:4], 2-byte unsigned LE.

        :returns: USB port C2 power or default int value.
        """
        return self._parse_int("ab", begin=2)

    @property
    def usb_port_a1(self) -> PortStatus:
        """USB A1 Port Status.

        Tag ``ae``, MQTT offset 00 → data[1], 1-byte unsigned.

        :returns: Status of the USB A1 port.
        """
        return PortStatus(self._parse_int("ae", begin=1, end=2))

    @property
    def usb_a1_power(self) -> int:
        """USB A1 Power.

        Tag ``ae``, MQTT offset 01 → data[2:4], 2-byte unsigned LE.

        :returns: USB port A1 power or default int value.
        """
        return self._parse_int("ae", begin=2)

    @property
    def usb_port_a2(self) -> PortStatus:
        """USB A2 Port Status.

        Tag ``af``, MQTT offset 00 → data[1], 1-byte unsigned.

        :returns: Status of the USB A2 port.
        """
        return PortStatus(self._parse_int("af", begin=1, end=2))

    @property
    def usb_a2_power(self) -> int:
        """USB A2 Power.

        Tag ``af``, MQTT offset 01 → data[2:4], 2-byte unsigned LE.

        :returns: USB port A2 power or default int value.
        """
        return self._parse_int("af", begin=2)

    @property
    def max_battery_percentage(self) -> int:
        """Maximum charge percentage.

        Tag ``d9``, MQTT offset 03 → data[4], 1-byte unsigned.

        :returns: Battery charge percentage upper limit or default int value.
        """
        return self._parse_int("d9", begin=4, end=5)

    @property
    def display_timeout(self) -> int:
        """Display timeout limit in seconds.

        Tag ``a4``, MQTT offset 15 → data[16:18], 2-byte signed LE.

        :returns: Timeout limit of the display.
        """
        return self._parse_int("a4", begin=16, end=18)
