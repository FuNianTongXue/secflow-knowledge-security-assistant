@RestController class OAuthRegistrationController {
  PortfolioRepository portfolioRepository;
  @PostMapping Object registerWithOAuth(@RequestBody OAuthProfile profile) {
    Portfolio portfolio = new Portfolio();
    portfolio.setUser(profile.getUser());
    portfolio.setBalance(BigDecimal.ZERO);
    return portfolioRepository.save(portfolio);
  }
}
