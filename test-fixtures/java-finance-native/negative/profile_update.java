@RestController class ProfileController {
  UserRepository repository;
  @PutMapping Object updateProfile(@RequestBody UserProfile profile) {
    return repository.save(profile);
  }
}
