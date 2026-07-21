@RestController class OrderPreviewController {
  @PostMapping MatchingOrderDTO preview(@RequestBody MatchingOrder order) {
    MatchingOrderDTO dto = new MatchingOrderDTO();
    dto.setMatchRatio(order.getMatchRatio());
    dto.setMaxAmount(order.getMaxAmount());
    dto.setRemainingAmount(order.getRemainingAmount());
    return dto;
  }
}
