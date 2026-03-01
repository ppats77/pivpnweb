(function() {
  var ua = navigator.userAgent;
  if (/Android|webOS|iPhone|iPad|iPod|BlackBerry|Windows Phone/i.test(ua)) {
    document.body.classList.add('mobile');
  }
})();
