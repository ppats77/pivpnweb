(function() {
  var showBtn = document.getElementById('show-form');
  var showBtn1 = document.getElementById('show-form1');
  var overlay = document.getElementById('popup-overlay');
  var popup = document.getElementById('popup');
  var closeBtn = document.getElementById('close-form');

  function openPopup() {
    overlay.classList.remove('hidden');
    popup.classList.remove('hidden');
  }

  function closePopup() {
    overlay.classList.add('hidden');
    popup.classList.add('hidden');
    document.getElementById('form').reset();
  }

  if (showBtn) showBtn.addEventListener('click', openPopup);
  if (showBtn1) showBtn1.addEventListener('click', openPopup);
  if (closeBtn) closeBtn.addEventListener('click', closePopup);
  if (overlay) overlay.addEventListener('click', closePopup);
})();
