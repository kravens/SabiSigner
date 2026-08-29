# Must import test base before the Controller
from base import FlowTest, FlowStep

from unittest.mock import patch

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.models.seed import Seed
from seedsigner.usb.session import SessionState
from seedsigner.views.view import MainMenuView
from seedsigner.views import tools_views, usb_views



class TestUsbFlows(FlowTest):

    def test__usb_session__no_seed__flow(self):
        """
        With no seed loaded there is nothing a USB host could be given, so the flow says
        so and goes back rather than putting the device on the bus.
        """
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.USB),
            FlowStep(usb_views.UsbSessionView, screen_return_value=0),
            FlowStep(tools_views.ToolsMenuView),
        ])


    def test__usb_session__cancel_at_start__flow(self):
        """
        Declining the "device goes online" prompt must not start a gadget.
        """
        seed = Seed(mnemonic=["abandon "* 11 + "about"])
        self.controller.storage.set_pending_seed(seed)
        self.controller.storage.finalize_pending_seed()

        with patch("seedsigner.views.usb_views.UsbSessionRunner") as mock_runner:
            self.run_sequence([
                FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
                FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.USB),
                FlowStep(usb_views.UsbSessionView, button_data_selection=usb_views.UsbSessionView.CANCEL),
                FlowStep(tools_views.ToolsMenuView),
            ])

        mock_runner.assert_not_called()



class TestUsbConfirmations(FlowTest):
    """
    The confirmation callbacks are the whole security surface of the USB path, so they are
    tested directly rather than through the flow harness (a single View here displays many
    screens, which the flow harness is not shaped to express).
    """

    def _view(self) -> usb_views.UsbSessionView:
        view = usb_views.UsbSessionView()
        view.seed = Seed(mnemonic=["abandon "* 11 + "about"])
        return view


    def test__unknown_confirmation_kind_is_refused(self):
        """
        If protocol.py ever grows a request whose prompt was never written, the answer is
        no. A missing screen must never read as approval.
        """
        view = self._view()
        with patch.object(usb_views.UsbSessionView, "run_screen") as mock_run_screen:
            assert view._confirm("export_the_seed_please", {}) is False
            mock_run_screen.assert_not_called()


    def test__export_xpub_requires_the_first_button(self):
        view = self._view()
        with patch.object(usb_views.UsbSessionView, "run_screen") as mock_run_screen:
            mock_run_screen.return_value = 0
            assert view._confirm("export_xpub", {"path": "m/84'/0'/0'"}) is True

            mock_run_screen.return_value = 1
            assert view._confirm("export_xpub", {"path": "m/84'/0'/0'"}) is False

            # Backing out of the prompt is a refusal, not an approval.
            mock_run_screen.return_value = RET_CODE__BACK_BUTTON
            assert view._confirm("export_xpub", {"path": "m/84'/0'/0'"}) is False


    def test__authorize_coinjoin_shows_the_whole_budget(self):
        """
        This prompt grants unattended signing, so every limit it grants has to be on the
        screen the user is looking at.
        """
        view = self._view()
        details = {
            "coordinator": "wasabi.example",
            "account_path": "m/84'/0'/0'",
            "max_rounds": 7,
            "max_fee_per_round_sat": 500,
            "max_total_fee_sat": 3000,
        }
        with patch.object(usb_views.UsbSessionView, "run_screen") as mock_run_screen:
            mock_run_screen.return_value = 0
            assert view._confirm("authorize_coinjoin", details) is True

            body = mock_run_screen.call_args.kwargs["body"]
            assert "wasabi.example" in body
            assert "m/84'/0'/0'" in body
            assert "7" in body
            assert "3000" in body


    def test__a_hostile_coordinator_name_cannot_push_the_budget_off_the_screen(self):
        """
        Host-supplied strings are clamped before they are rendered. A 200-character
        coordinator that shoved the fee limit past the bottom edge would be a way to get an
        unattended-signing authorization approved without the user ever seeing its size.
        """
        view = self._view()
        details = {
            "coordinator": "A" * 200,
            "account_path": "m/84'/0'/0'",
            "max_rounds": 7,
            "max_fee_per_round_sat": 500,
            "max_total_fee_sat": 3000,
        }
        with patch.object(usb_views.UsbSessionView, "run_screen") as mock_run_screen:
            mock_run_screen.return_value = 0
            view._confirm("authorize_coinjoin", details)

            body = mock_run_screen.call_args.kwargs["body"]
            assert len(body.splitlines()[0]) <= usb_views.MAX_DISPLAYED_CHARS
            assert "3000" in body


    def test__an_unreadable_psbt_is_never_signed(self):
        """
        A transaction the device cannot summarize is a transaction the user cannot judge.
        """
        view = self._view()
        with patch.object(usb_views.UsbSessionView, "run_screen") as mock_run_screen:
            mock_run_screen.return_value = 0
            assert view._confirm("sign_psbt", {"psbt": object()}) is False


    def test__leaving_the_screen_stops_the_session(self):
        """
        The gadget must come off the bus when the user leaves, even if the screen raised.
        """
        seed = Seed(mnemonic=["abandon "* 11 + "about"])
        self.controller.storage.set_pending_seed(seed)
        self.controller.storage.finalize_pending_seed()

        view = usb_views.UsbSessionView()
        with patch("seedsigner.views.usb_views.UsbSessionRunner") as MockRunner:
            runner = MockRunner.return_value
            runner.state = SessionState.AWAITING_HELLO
            runner.authorization = None
            with patch.object(usb_views.UsbSessionView, "run_screen") as mock_run_screen:
                # seed auto-selected (only one), "device goes online" approved, then the
                # session screen returns as if the user pressed back.
                mock_run_screen.side_effect = [0, RET_CODE__BACK_BUTTON]
                view.run()

        runner.stop.assert_called_once()
