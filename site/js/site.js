/* GNULTE site behaviour: navigation toggle and terminal copy buttons.
   No dependencies, no framework, no build step. */
(function () {
  'use strict';

  var toggle = document.querySelector('.navtoggle');
  var menu = document.querySelector('.navlist');
  if (toggle && menu) {
    toggle.addEventListener('click', function () {
      var open = menu.classList.toggle('open');
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      toggle.textContent = open ? 'close' : 'menu';
    });
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    var area = document.createElement('textarea');
    area.value = text;
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    try { document.execCommand('copy'); } catch (e) { /* clipboard unavailable */ }
    document.body.removeChild(area);
    return Promise.resolve();
  }

  var buttons = document.querySelectorAll('.copy');
  for (var i = 0; i < buttons.length; i++) {
    buttons[i].addEventListener('click', function () {
      var terminal = this.closest('.terminal');
      var code = terminal && terminal.querySelector('code');
      if (!code) return;
      var button = this;
      copyText(code.textContent).then(function () {
        var previous = button.textContent;
        button.textContent = 'copied';
        setTimeout(function () { button.textContent = previous; }, 1500);
      });
    });
  }
})();
