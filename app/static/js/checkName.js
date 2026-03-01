function checkName() {
  var name = document.getElementById("name").value;

  if (!name.length) {
    alert("You cannot leave the name blank.");
    return false;
  }
  if (!/^[a-zA-Z][a-zA-Z0-9._@-]*$/.test(name)) {
    alert("Name must start with a letter and only contain alphanumeric characters and .-@_");
    return false;
  }
  return true;
}
