class SafeSettlementConsumer {
  IdempotencyRepository idempotencyRepository;
  SettlementRepository repository;
  @KafkaListener @Transactional Object settle(SettlementEvent event) {
    idempotencyRepository.insertUnique(event.getMessageId());
    return repository.credit(event.getAccountId(), event.getAmount());
  }
}
