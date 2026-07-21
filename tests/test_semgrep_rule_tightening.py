from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class SemgrepRuleTighteningTests(unittest.TestCase):
    def test_http_client_execute_and_regex_compile_are_not_sql_or_xpath_sinks(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        import java.util.regex.Pattern;
        import org.apache.http.client.HttpClient;
        import org.apache.http.client.methods.HttpGet;
        import javax.servlet.http.HttpServletRequest;

        class Demo {
          void proxy(HttpServletRequest request, HttpClient client) throws Exception {
            String url = request.getParameter("url");
            client.execute(new HttpGet(url));
          }

          Pattern regex(HttpServletRequest request) {
            String regex = request.getParameter("regex");
            return Pattern.compile(regex);
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertNotIn("sql-injection", rule_ids)
        self.assertNotIn("xpath-injection", rule_ids)

    def test_xpath_variable_named_xp_is_still_detected(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        import javax.servlet.http.HttpServletRequest;
        import javax.xml.xpath.XPath;
        import javax.xml.xpath.XPathFactory;

        class Demo {
          void handle(HttpServletRequest request) throws Exception {
            String param = request.getHeader("employee");
            XPath xp = XPathFactory.newInstance().newXPath();
            String expression = "/Employees/Employee[@emplid='" + param + "']";
            xp.compile(expression);
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertIn("xpath-injection", rule_ids)

    def test_finance_money_float_and_bigdecimal_double_literal_are_detected(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        import java.math.BigDecimal;

        class Settlement {
          private double totalAmount;
          private Float refundFee = 1.2F;
          BigDecimal fee() {
            return new BigDecimal(0.01);
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertIn("finance.money-float", rule_ids)
        self.assertIn("finance.bigdecimal-from-double-literal", rule_ids)

    def test_finance_bigdecimal_from_double_variable_is_detected(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        import java.math.BigDecimal;

        class PaypalPayment {
          BigDecimal createPayment(Double totalAmount) {
            return new BigDecimal(totalAmount);
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertIn("finance.bigdecimal-from-double-variable", rule_ids)

    def test_finance_bigdecimal_from_string_variable_is_not_reported(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        import java.math.BigDecimal;

        class Settlement {
          BigDecimal parse(String totalAmount) {
            return new BigDecimal(totalAmount);
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertNotIn("finance.bigdecimal-from-double-variable", rule_ids)

    def test_finance_post_payment_without_idempotency_is_detected(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        import org.springframework.web.bind.annotation.PostMapping;

        class PaymentController {
          private PaymentService paymentService;

          @PostMapping("/pay")
          PaymentResult pay(PayCommand command) {
            return paymentService.createPayment(command);
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertIn("finance.missing-idempotency-key", rule_ids)

    def test_finance_post_payment_with_idempotency_key_is_not_reported(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        import jakarta.servlet.http.HttpServletRequest;
        import org.springframework.web.bind.annotation.PostMapping;

        class PaymentController {
          private PaymentService paymentService;

          @PostMapping("/pay")
          PaymentResult pay(HttpServletRequest request, PayCommand command) {
            String key = request.getHeader("Idempotency-Key");
            return paymentService.createPayment(command, key);
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertNotIn("finance.missing-idempotency-key", rule_ids)

    def test_finance_put_transfer_without_idempotency_is_detected(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        import org.springframework.web.bind.annotation.PutMapping;

        class WalletController {
          private WalletService walletService;

          @PutMapping("/fundtran/{source}/{target}/{amount}")
          TransferResult walletToWalletTransfer(String source, String target, Double amount) {
            return walletService.fundTransfer(source, target, amount);
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertIn("finance.missing-idempotency-key", rule_ids)

    def test_non_finance_put_update_without_idempotency_is_not_reported(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        import org.springframework.web.bind.annotation.PutMapping;

        class ProfileController {
          private ProfileService profileService;

          @PutMapping("/profile/{id}")
          Profile updateProfile(String id, Profile profile) {
            return profileService.updateProfile(id, profile);
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertNotIn("finance.missing-idempotency-key", rule_ids)

    def test_bank_account_binding_without_money_movement_is_not_idempotency_finding(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        import org.springframework.web.bind.annotation.PostMapping;

        class BankAccountController {
          private BankAccountService bankService;

          @PostMapping("/{id}")
          BankAccount addBankAccountToWallet(BankAccount bankAccount, String uniqueId) {
            return bankService.addBank(bankAccount, uniqueId);
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertNotIn("finance.missing-idempotency-key", rule_ids)

    def test_bill_record_update_without_payment_action_is_not_idempotency_finding(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        import org.springframework.web.bind.annotation.PutMapping;

        class BillController {
          private BillRepository billRepository;

          @PutMapping("/{id}")
          Bill updateBill(Bill updateBill, Bill billDetails) {
            updateBill.setBillAmount(billDetails.getBillAmount());
            return billRepository.save(updateBill);
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertNotIn("finance.missing-idempotency-key", rule_ids)

    def test_finance_money_update_without_transaction_is_detected(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        class AccountService {
          private AccountRepository accountRepository;

          void transfer(TransferCommand command) {
            accountRepository.update(command.fromAccount(), command.amount());
            accountRepository.update(command.toAccount(), command.amount());
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertIn("finance.money-operation-without-transaction", rule_ids)

    def test_finance_money_update_with_transaction_is_not_reported(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        import org.springframework.transaction.annotation.Transactional;

        class AccountService {
          private AccountRepository accountRepository;

          @Transactional
          void transfer(TransferCommand command) {
            accountRepository.update(command.fromAccount(), command.amount());
            accountRepository.update(command.toAccount(), command.amount());
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertNotIn("finance.money-operation-without-transaction", rule_ids)

    def test_finance_add_money_without_transaction_is_detected(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        class WalletService {
          private WalletRepository walletRepository;
          private BankAccountRepository bankAccountRepository;

          Customer addMoney(String uniqueId, Double amount) {
            bankAccountRepository.save(new BankAccount());
            walletRepository.save(new Wallet());
            return new Customer();
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertIn("finance.money-operation-without-transaction", rule_ids)

    def test_bank_account_binding_without_money_movement_is_not_transaction_finding(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        class BankAccountService {
          private BankAccountRepository bankAccountRepository;

          BankAccount addBank(BankAccount bankAccount) {
            return bankAccountRepository.save(bankAccount);
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertNotIn("finance.money-operation-without-transaction", rule_ids)

    def test_bill_record_update_without_payment_action_is_not_transaction_finding(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        class BillService {
          private BillRepository billRepository;

          Bill updateBill(Bill updateBill, Bill billDetails) {
            updateBill.setBillAmount(billDetails.getBillAmount());
            return billRepository.save(updateBill);
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertNotIn("finance.money-operation-without-transaction", rule_ids)

    def test_finance_sdk_amount_setter_without_persistence_is_not_transaction_finding(self) -> None:
        if not shutil.which("semgrep"):
            self.skipTest("semgrep CLI is not available")

        java = """
        class PaypalService {
          Payment createPayment(Double totalAmount) {
            Transaction transaction = new Transaction();
            transaction.setAmount(new Amount("USD", new BigDecimal(totalAmount).toString()));
            return new Payment();
          }
        }
        """

        findings = self._run_semgrep(java)
        rule_ids = {finding["check_id"].split("secflow.java.")[-1] for finding in findings}

        self.assertNotIn("finance.money-operation-without-transaction", rule_ids)

    @staticmethod
    def _run_semgrep(java_source: str) -> list[dict[str, object]]:
        root = Path(__file__).resolve().parents[1]
        rules = root / "config" / "semgrep" / "java-security.yml"
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "Demo.java"
            output = Path(temp_dir) / "results.json"
            target.write_text(java_source, encoding="utf-8")
            completed = subprocess.run(
                [
                    "semgrep",
                    "scan",
                    "--quiet",
                    "--config",
                    str(rules),
                    "--json-output",
                    str(output),
                    "--metrics=off",
                    "--disable-version-check",
                    str(target),
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            if completed.returncode != 0:
                raise AssertionError(completed.stderr or completed.stdout)
            return json.loads(output.read_text(encoding="utf-8")).get("results") or []


if __name__ == "__main__":
    unittest.main()
