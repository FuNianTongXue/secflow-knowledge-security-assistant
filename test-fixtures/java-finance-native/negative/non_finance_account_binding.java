@RestController class BankAccountBindingController {
  BankAccountRepository repository;
  @PostMapping Object bindAccount(@RequestBody BankAccountBinding binding) {
    return repository.save(binding);
  }
}
