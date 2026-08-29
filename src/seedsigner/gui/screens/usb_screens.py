"""
Screens for the USB session.

The interesting one is UsbSessionScreen. Every other screen in the app is driven by
`HardwareButtons.wait_for()`, which blocks until a GPIO goes low; a USB session cannot be
driven that way, because messages arrive from the host while nobody is touching a button.
So this screen owns its own loop and polls, the same way the camera preview screen does.
"""
import time

from dataclasses import dataclass
from gettext import gettext as _
from typing import Callable, ClassVar

from seedsigner.gui.components import GUIConstants, TextArea
from seedsigner.gui.screens.screen import (BaseTopNavScreen, ButtonListScreen,
    ButtonOption, RET_CODE__BACK_BUTTON, WarningEdgesMixin)
from seedsigner.hardware.buttons import HardwareButtonsConstants
from seedsigner.helpers.l10n import mark_for_translation as _mft


@dataclass
class UsbSessionScreen(BaseTopNavScreen):
    """
    Live view of a USB session.

    `pump` is called on every pass of the loop. It returns:
        * None                  -- nothing changed, do not redraw
        * (headline, body)      -- new status text, redraw
        * an int                -- exit the screen and return that value to the View

    The callable does the actual USB work and may itself display other screens (a
    confirmation prompt, the pairing digits). That is safe because the loop does not hold
    the renderer lock between passes; it claims the lock only to draw.
    """
    title: str = _mft("USB Session")
    status_headline: str = ""
    status_body: str = ""
    pump: Callable = None

    # How long each pass waits on the socket before giving the buttons another look. Short
    # enough that the back button still feels instant, long enough that an idle session is
    # not a spin loop on a single-core Pi Zero. ClassVar so the dataclass does not turn it
    # into a constructor argument.
    POLL_INTERVAL: ClassVar[float] = 0.1


    def __post_init__(self):
        super().__post_init__()
        self._build_body()


    def _build_body(self):
        """Rebuild the body text areas around the (unchanging) top nav."""
        self.components = [self.top_nav]

        next_y = self.top_nav.height + GUIConstants.COMPONENT_PADDING

        if self.status_headline:
            headline = TextArea(
                text=self.status_headline,
                screen_y=next_y,
                font_name=GUIConstants.get_body_font_name(),
                font_size=GUIConstants.get_top_nav_title_font_size(),
                font_color=GUIConstants.ACCENT_COLOR,
            )
            self.components.append(headline)
            next_y += headline.height + GUIConstants.COMPONENT_PADDING

        if self.status_body:
            self.components.append(TextArea(
                text=self.status_body,
                screen_y=next_y,
                height=max(1, self.canvas_height - next_y - GUIConstants.EDGE_PADDING),
            ))


    def _redraw(self):
        with self.renderer.lock:
            self._render()
            self.renderer.show_image()


    def _run(self):
        while True:
            # KEY_LEFT only, never a click: the click that selected "USB" on the previous
            # menu may still be held down when this loop starts, and reading it here would
            # bounce the user straight back out.
            if self.hw_inputs.check_for_low(HardwareButtonsConstants.KEY_LEFT):
                return RET_CODE__BACK_BUTTON

            update = self.pump() if self.pump else None

            if isinstance(update, int):
                return update

            if update is not None:
                self.status_headline, self.status_body = update
                self._build_body()
                self._redraw()

            # `pump` is expected to do its own blocking wait on the USB socket. If it
            # returned immediately anyway, don't let the loop become a busy-wait.
            if update is None:
                time.sleep(0.01)



@dataclass
class UsbPairingScreen(ButtonListScreen):
    """
    Six digits derived from the handshake transcript, shown on the device.

    This is the only defense against something sitting in the middle of the cable. The
    digits come from a hash of both public keys, so an interposer that swapped either key
    produces different digits on the two ends and the user sees it. The wording has to
    push the user to actually compare rather than to press the first button.
    """
    title: str = _mft("Pairing Code")
    sas: str = "000000"
    is_bottom_list: bool = True


    def __post_init__(self):
        self.button_data = [
            ButtonOption(_mft("Codes match")),
            ButtonOption(_mft("Cancel")),
        ]
        super().__post_init__()

        next_y = self.top_nav.height + GUIConstants.COMPONENT_PADDING

        # Grouped 3+3 and rendered large: the user has to compare this against the
        # computer's screen, so it has to be readable at a glance and hard to misread.
        digits = TextArea(
            text=f"{self.sas[:3]} {self.sas[3:]}",
            screen_y=next_y,
            font_name=GUIConstants.get_body_font_name(),
            font_size=GUIConstants.get_top_nav_title_font_size() + 12,
            font_color=GUIConstants.ACCENT_COLOR,
        )
        self.components.append(digits)
        next_y += digits.height + GUIConstants.COMPONENT_PADDING

        self.components.append(TextArea(
            text=_("Confirm this code matches the one on your computer."),
            screen_y=next_y,
            height=max(1, self.buttons[0].screen_y - next_y),
        ))



@dataclass
class UsbConfirmScreen(WarningEdgesMixin, ButtonListScreen):
    """
    The prompt shown for anything a USB host asks the device to reveal or sign.

    Deliberately not built on WarningScreen. That screen spends its vertical budget on a
    large status icon, which leaves room for about three lines of body text; a coinjoin
    authorization has to show a coordinator, an account, a round limit and a fee limit, and
    a prompt that pushes half of what it is granting off the bottom of the screen is worse
    than no prompt at all. The pulsing warning edges carry the alarm instead, and every
    remaining pixel goes to the text the user has to read before pressing yes.
    """
    title: str = _mft("Confirm")
    status_headline: str = None
    body: str = ""
    is_bottom_list: bool = True


    def __post_init__(self):
        super().__post_init__()

        next_y = self.top_nav.height + int(GUIConstants.COMPONENT_PADDING / 2)

        if self.status_headline:
            headline = TextArea(
                text=self.status_headline,
                screen_y=next_y,
                font_color=self.status_color,
                auto_line_break=False,  # Force the headline onto one line
            )
            self.components.append(headline)
            next_y += headline.height + int(GUIConstants.COMPONENT_PADDING / 2)

        available_height = self.buttons[0].screen_y - next_y - int(GUIConstants.COMPONENT_PADDING / 2)
        self.components.append(TextArea(
            text=self.body,
            screen_y=next_y,
            height=max(1, available_height),
            font_size=GUIConstants.get_body_font_size() - 2,
        ))
