class SettlementConsumer {
  SettlementRepository repository;
  @KafkaListener Object settle(SettlementEvent event) {
    return repository.credit(event.getAccountId(), event.getAmount());
  }
}
