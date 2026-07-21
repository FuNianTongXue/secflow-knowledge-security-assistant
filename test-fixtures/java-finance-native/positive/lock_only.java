@RestController class LockOnlyController {
  LockService lockService;
  PaymentRepository paymentRepository;
  @PostMapping @Transactional Object pay(@RequestBody PaymentRequest request) {
    lockService.tryLock(request.getRequestNo());
    return paymentRepository.debit(request.getRequestNo(), request.getAmount());
  }
}
