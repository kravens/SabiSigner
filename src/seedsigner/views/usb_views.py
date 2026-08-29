"""
Views for the USB session.

The flow is: pick a seed, acknowledge that the device is about to appear on the host's
bus, then sit in a single long-lived screen for as long as the session lasts. Leaving that
screen unbinds the gadget, which is what makes "USB off by default" a property of the
hardware state rather than a promise in a settings menu.

Everything a host can ask for lands in `_confirm()`, which is the only place in the USB
path where a human is asked anything -- except a coinjoin round, which is checked by
policy.py against the budget the user already approved here.
"""
import logging

from gettext import gettext as _

from seedsigner.gui.components import GUIConstants, SeedSignerIconConstants
from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.gui.screens.screen import (ButtonOption, ErrorScreen, ButtonListScreen,
    WarningScreen)
from seedsigner.gui.screens.usb_screens import (UsbConfirmScreen, UsbPairingScreen,
    UsbSessionScreen)
from seedsigner.helpers.l10n import mark_for_translation as _mft
from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.usb.session import SessionState, UsbSessionRunner

from .view import View, Destination, BackStackView

logger = logging.getLogger(__name__)


# Longest host-supplied string that gets rendered verbatim on a prompt. The protocol layer
# already caps these fields, but its cap is about memory; this one is about legibility. A
# 256-character "coordinator" that pushed the fee limit off the bottom of an authorization
# prompt would be an attack on the user's eyes, which is the only thing standing between a
# hostile host and an approved request.
MAX_DISPLAYED_CHARS = 24

# The session screen has a whole screen for its body rather than a few lines beside a
# prompt, so it can afford more -- but the reason a session ended can quote host-supplied
# text, and it still has to stay on the screen.
MAX_STATUS_CHARS = 120


def _short(value) -> str:
    """Clamp a host-supplied value to something that fits on a 240px screen."""
    text = str(value)
    if len(text) <= MAX_DISPLAYED_CHARS:
        return text
    return text[:MAX_DISPLAYED_CHARS - 1] + "\u2026"



class UsbSessionView(View):
    """
    Owns one USB session from cable to teardown.

    The session runs in this thread. `_pump()` is handed to the screen, which calls it on
    every pass of its loop; that keeps the USB work and the drawing on the same thread, so
    a confirmation prompt can be rendered from inside a request handler without any
    cross-thread handoff.
    """
    START = ButtonOption("Start USB session")
    CANCEL = ButtonOption("Cancel")

    SIGN = ButtonOption("Sign")
    EXPORT = ButtonOption("Export")
    AUTHORIZE = ButtonOption("Authorize")


    def __init__(self):
        super().__init__()
        self.seed = None
        self.runner: UsbSessionRunner = None

        # A screensaver during a coinjoin would blank the screen while the device keeps
        # signing. The user needs to be able to see what their device is doing.
        self.is_screensaver_allowed = False

        # Set whenever something else has drawn over the session screen, so the next
        # `_pump()` redraws it even if the status text is unchanged.
        self._force_redraw = False


    # -- flow --------------------------------------------------------------------------

    def run(self):
        seeds = self.controller.storage.seeds
        if not seeds:
            self.run_screen(
                WarningScreen,
                title=_("USB"),
                status_headline=_("No seed loaded"),
                text=_("Load a seed first. A USB session can only use a seed you have already scanned."),
                button_data=[ButtonOption(_mft("OK"))],
            )
            return Destination(BackStackView)

        self.seed = self._select_seed(seeds)
        if self.seed is None:
            return Destination(BackStackView)

        if not self._confirm_start():
            return Destination(BackStackView)

        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
        self.runner = UsbSessionRunner(
            seed=self.seed,
            network=network,
            confirm=self._confirm,
            on_pairing=self._on_pairing,
        )

        try:
            self.runner.start()
        except Exception as e:
            logger.exception("could not start the USB session")
            self.run_screen(
                ErrorScreen,
                title=_("USB"),
                status_headline=_("USB unavailable"),
                text=_("The USB gadget could not be started: {}").format(_short(e)),
                button_data=[ButtonOption(_mft("OK"))],
            )
            return Destination(BackStackView)

        headline, body = self._status()
        try:
            self.run_screen(
                UsbSessionScreen,
                title=_("USB Session"),
                status_headline=headline,
                status_body=body,
                pump=self._pump,
            )
        finally:
            # Whatever happened -- clean exit, exception, host misbehaving -- the gadget
            # comes off the bus and the session keys go away with the runner.
            self.runner.stop()

        return Destination(BackStackView)


    def _select_seed(self, seeds) -> object:
        if len(seeds) == 1:
            return seeds[0]

        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
        button_data = [
            ButtonOption(seed.get_fingerprint(network), SeedSignerIconConstants.FINGERPRINT, icon_color="blue")
            for seed in seeds
        ]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("USB Session"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return None
        return seeds[selected_menu_num]


    def _confirm_start(self) -> bool:
        """
        The last screen before the device becomes visible to the computer.

        Worth its own prompt: until the user presses this button the port is powered but
        enumerates nothing, and that is a property they should know they are giving up.
        """
        selected_menu_num = self.run_screen(
            UsbConfirmScreen,
            title=_("USB Session"),
            status_headline=_("Device goes online"),
            body=_("Your computer sees this device only while this screen is open. Your seed never leaves it."),
            button_data=[self.START, self.CANCEL],
        )
        return selected_menu_num == 0


    # -- session loop ------------------------------------------------------------------

    def _status(self) -> tuple:
        state = self.runner.state

        if state == SessionState.AWAITING_HELLO:
            return (_("Waiting"), _("Start the session on your computer."))

        if state == SessionState.AWAITING_PAIRING:
            return (_("Pairing"), _("Compare the code with your computer."))

        if state == SessionState.ENDED:
            # The reason can quote text the host chose (a JSON parse error, for instance),
            # so it is clamped before it reaches a TextArea.
            reason = self.runner.last_error
            detail = reason[:MAX_STATUS_CHARS] if reason else _("Closed.")
            return (_("Session ended"), detail + "\n\n" + _("Press left to go back."))

        authorization = self.runner.authorization
        if authorization is None:
            return (_("Connected"), _("Requests will be shown here for approval."))

        # TRANSLATOR_NOTE: Remaining coinjoin budget: rounds left, then fee sats left.
        return (_("Coinjoin"), _("{} of {} rounds left\n{} sats fee budget left").format(
            authorization.rounds_remaining,
            authorization.max_rounds,
            authorization.fee_remaining_sat,
        ))


    def _pump(self):
        """
        One pass of the session loop. See UsbSessionScreen for the return contract.
        """
        before = self._status()

        self.runner.pump(timeout=UsbSessionScreen.POLL_INTERVAL)

        if self.runner.state == SessionState.AWAITING_PAIRING:
            # complete_pairing() draws the digits and blocks on the user, so it has to run
            # here in the screen's own thread rather than inside the runner's I/O path.
            self.runner.complete_pairing()
            self._force_redraw = True

        after = self._status()
        if self._force_redraw or after != before:
            self._force_redraw = False
            return after
        return None


    # -- confirmations -----------------------------------------------------------------

    def _on_pairing(self, sas: str) -> bool:
        self._force_redraw = True
        selected_menu_num = self.run_screen(UsbPairingScreen, sas=sas)
        return selected_menu_num == 0


    def _confirm(self, kind: str, details: dict) -> bool:
        # Anything drawn from here covers the session screen, so it has to come back.
        self._force_redraw = True

        if kind == "export_xpub":
            return self._confirm_export_xpub(details)

        if kind == "sign_psbt":
            return self._confirm_sign_psbt(details)

        if kind == "authorize_coinjoin":
            return self._confirm_authorize_coinjoin(details)

        # A confirmation kind this View does not recognize means protocol.py grew a new
        # request and nobody wrote its prompt. The safe answer to a question the device
        # cannot state is no.
        logger.error("no confirmation screen for %r; refusing", kind)
        return False


    def _confirm_export_xpub(self, details: dict) -> bool:
        selected_menu_num = self.run_screen(
            UsbConfirmScreen,
            title=_("Export Xpub"),
            status_headline=_("Privacy leak!"),
            status_color=GUIConstants.DIRE_WARNING_COLOR,
            body=_("Send the account xpub for {} to your computer? It reveals every address in that account.").format(_short(details["path"])),
            button_data=[self.EXPORT, self.CANCEL],
        )
        return selected_menu_num == 0


    def _confirm_sign_psbt(self, details: dict) -> bool:
        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
        try:
            parser = PSBTParser(details["psbt"], seed=self.seed, network=network)
        except Exception as e:
            # A transaction the device cannot describe is a transaction the user cannot
            # approve. Refuse rather than showing an amount we are not sure of.
            logger.exception("could not parse a psbt received over USB")
            self.run_screen(
                ErrorScreen,
                title=_("Sign Transaction"),
                status_headline=_("Cannot read PSBT"),
                text=_("This transaction could not be read, so it was not signed."),
                button_data=[ButtonOption(_mft("OK"))],
            )
            return False

        body = _("Send {} sats\nFee {} sats\nTo {} address(es)").format(
            parser.spend_amount,
            parser.fee_amount,
            parser.num_destinations,
        )
        selected_menu_num = self.run_screen(
            UsbConfirmScreen,
            title=_("Sign Transaction"),
            status_headline=_("Sign this?"),
            body=body,
            button_data=[self.SIGN, self.CANCEL],
        )
        return selected_menu_num == 0


    def _confirm_authorize_coinjoin(self, details: dict) -> bool:
        """
        The one prompt that grants signing power for later requests, so it shows the whole
        budget it is granting: which coordinator, which account, how many rounds, how many
        sats of fees. Nothing beyond these limits can be signed without coming back here.
        """
        body = _("{}\n{}\nMax {} rounds\nMax {} sats of fees").format(
            _short(details["coordinator"]),
            _short(details["account_path"]),
            details["max_rounds"],
            details["max_total_fee_sat"],
        )
        selected_menu_num = self.run_screen(
            UsbConfirmScreen,
            title=_("Coinjoin"),
            # TRANSLATOR_NOTE: Warns that approving this grants signing without further prompts
            status_headline=_("Signs unattended!"),
            status_color=GUIConstants.DIRE_WARNING_COLOR,
            body=body,
            button_data=[self.AUTHORIZE, self.CANCEL],
        )
        return selected_menu_num == 0
