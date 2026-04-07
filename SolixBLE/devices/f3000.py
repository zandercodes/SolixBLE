"""F3000 power station model.

.. moduleauthor:: Harvey Lelliott (flip-dots) <harveylelliott@duck.com>

"""

import logging
from datetime import datetime, timedelta

from ..const import (
    DEFAULT_METADATA_FLOAT,
    DEFAULT_METADATA_INT,
    DEFAULT_METADATA_STRING,
)
from ..device import SolixBLEDevice
from ..states import ChargingStatusF3800, PortStatus

_LOGGER = logging.getLogger(__name__)


class F3000(SolixBLEDevice):
    """
    F3000 Power Station.

    Use this class to connect and monitor a F3000 power station.
    This model is also known as the A1782.

    The F3000 is a 3072Wh portable power station with LiFePO4 batteries,
    3600W inverter output, dual MPPT solar input (up to 2400W), and
    expandable capacity with BP3000 expansion batteries.

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

    @property
    def hours_remaining(self) -> float:
        """Time remaining to full/empty.

        Note that any hours over 24 are overflowed to the
        days remaining. Use time_remaining if you want
        days to be included.

        :returns: Hours remaining or default float value.
        """
        if self._data is None:
            return DEFAULT_METADATA_FLOAT

        return round(divmod(self.time_remaining, 24)[1], 1)

    @property
    def days_remaining(self) -> int:
        """Time remaining to full/empty.

        Note that any partial days are overflowed into
        the hours remaining. Use time_remaining if you want
        hours to be included.

        :returns: Days remaining or default int value.
        """
        if self._data is None:
            return DEFAULT_METADATA_INT

        return round(divmod(self.time_remaining, 24)[0])

    @property
    def time_remaining(self) -> float:
        """Time remaining to full/empty in hours.

        :returns: Hours remaining or default float value.
        """
        return (
            self._parse_int("a4", begin=1) / 10.0
            if self._data is not None
            else DEFAULT_METADATA_FLOAT
        )

    @property
    def timestamp_remaining(self) -> datetime | None:
        """Timestamp of when device will be full/empty.

        :returns: Timestamp of when will be full/empty or None.
        """
        if self._data is None:
            return None
        return datetime.now() + timedelta(hours=self.time_remaining)

    @property
    def ac_power_in(self) -> int:
        """AC Power In.

        :returns: Total AC power in or default int value.
        """
        return self._parse_int("a5", begin=1)

    @property
    def ac_power_out(self) -> int:
        """AC Power Out.

        :returns: Total AC power out or default int value.
        """
        return self._parse_int("a6", begin=1)

    @property
    def usb_c1_power(self) -> int:
        """USB C1 Power.

        :returns: USB port C1 power or default int value.
        """
        return self._parse_int("a7", begin=1)

    @property
    def usb_c2_power(self) -> int:
        """USB C2 Power.

        :returns: USB port C2 power or default int value.
        """
        return self._parse_int("a8", begin=1)

    @property
    def usb_a1_power(self) -> int:
        """USB A1 Power.

        :returns: USB port A1 power or default int value.
        """
        return self._parse_int("a9", begin=1)

    @property
    def usb_a2_power(self) -> int:
        """USB A2 Power.

        :returns: USB port A2 power or default int value.
        """
        return self._parse_int("aa", begin=1)

    @property
    def dc_output(self) -> PortStatus:
        """DC Port Status.

        :returns: Status of the DC port.
        """
        return PortStatus(self._parse_int("ab", begin=1))

    @property
    def battery_percentage(self) -> int:
        """Battery Percentage.

        :returns: Percentage charge of battery or default int value.
        """
        return self._parse_int("ad", begin=1)

    @property
    def solar_power_in(self) -> int:
        """Total Solar Power In.

        :returns: Total solar power in or default int value.
        """
        return self._parse_int("ae", begin=1)

    @property
    def solar_pv_1_power_in(self) -> int:
        """Solar Power In for MPPT channel 1.

        :returns: Solar power in or default int value.
        """
        return self._parse_int("af", begin=1)

    @property
    def solar_pv_2_power_in(self) -> int:
        """Solar Power In for MPPT channel 2.

        :returns: Solar power in or default int value.
        """
        return self._parse_int("b0", begin=1)

    @property
    def battery_charge_power(self) -> int:
        """Battery charging power (AC+DC).

        :returns: Total battery power in or default int value.
        """
        return self._parse_int("b1", begin=1)

    @property
    def power_out(self) -> int:
        """Total Power Out.

        :returns: Total power out or default int value.
        """
        return self._parse_int("b2", begin=1)

    @property
    def battery_discharge_power(self) -> int:
        """Battery discharging power (AC+DC).

        :returns: Total battery power out or default int value.
        """
        return self._parse_int("b4", begin=1)

    @property
    def software_version(self) -> str:
        """Main software version.

        :returns: Firmware version or default str value.
        """
        if self._data is None:
            return DEFAULT_METADATA_STRING

        return ".".join([digit for digit in str(self._parse_int("b5", begin=1))])

    @property
    def software_version_expansion(self) -> str:
        """Software version of any expansion batteries.

        If there is no expansion battery then it will be "0".

        :returns: Firmware version or default str value.
        """
        if self._data is None:
            return DEFAULT_METADATA_STRING

        return ".".join([digit for digit in str(self._parse_int("ba", begin=1))])

    @property
    def ac_output(self) -> PortStatus:
        """AC Port Status.

        PortStatus.NOT_CONNECTED signifies off.
        PortStatus.OUTPUT signifies on.

        :returns: Status of the AC port.
        """
        return PortStatus(self._parse_int("bc", begin=1))

    @property
    def charging_status(self) -> ChargingStatusF3800:
        """Charging status of the device.

        :returns: Status of charging.
        """
        return ChargingStatusF3800(self._parse_int("bd", begin=1))

    @property
    def temperature(self) -> int:
        """Temperature of the unit (C).

        :returns: Temperature of the unit in degrees C.
        """
        return self._parse_int("be", begin=1, signed=True)

    @property
    def battery_percentage_aggregate(self) -> int:
        """Battery Percentage average across all batteries.

        :returns: Percentage charge of battery or default int value.
        """
        return self._parse_int("c0", begin=1)

    @property
    def max_battery_percentage(self) -> int:
        """Maximum charge percentage.

        :returns: Battery charge percentage upper limit or default int value.
        """
        return self._parse_int("c1", begin=1)

    @property
    def usb_port_c1(self) -> PortStatus:
        """USB C1 Port Status.

        :returns: Status of the USB C1 port.
        """
        return PortStatus(self._parse_int("c2", begin=1))

    @property
    def usb_port_c2(self) -> PortStatus:
        """USB C2 Port Status.

        :returns: Status of the USB C2 port.
        """
        return PortStatus(self._parse_int("c3", begin=1))

    @property
    def usb_port_a1(self) -> PortStatus:
        """USB A1 Port Status.

        :returns: Status of the USB A1 port.
        """
        return PortStatus(self._parse_int("c4", begin=1))

    @property
    def usb_port_a2(self) -> PortStatus:
        """USB A2 Port Status.

        :returns: Status of the USB A2 port.
        """
        return PortStatus(self._parse_int("c5", begin=1))

    @property
    def serial_number(self) -> str:
        """Device serial number.

        :returns: Device serial number or default str value.
        """
        return self._parse_string("cc", begin=1)

    @property
    def display_timeout(self) -> int:
        """Display timeout limit in seconds.

        :returns: Timeout limit of the display.
        """
        return self._parse_int("cf", begin=1)
