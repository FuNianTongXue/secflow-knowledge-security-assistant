@RestController class WalletPasswordController {
  CustomerRepository customerRepository;
  @PostMapping Object changePassword(@RequestBody PasswordChange command) {
    Customer customer = customerRepository.findById(command.getCustomerId());
    customer.setPassword(command.getPassword());
    return customerRepository.save(customer);
  }
}
