@RestController class LimitConfigController {
  LimitConfigRepository repository;
  @PutMapping Object updateLimit(@RequestBody LimitConfig config) {
    return repository.save(config);
  }
}
