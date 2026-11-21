/* GNULTE engineering-workstation site behaviour.
   Navigation, copy buttons, install tabs and topology detail.
   No dependencies, no framework, no build step. */
(function () {
  'use strict';

  var toggle = document.querySelector('.navtoggle');
  var nav = document.querySelector('.site-nav');

  if (toggle && nav) {
    toggle.addEventListener('click', function () {
      var open = nav.classList.toggle('open');
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
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.top = '0';
    area.style.left = '-9999px';
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    document.body.removeChild(area);
    return ok ? Promise.resolve() : Promise.reject(new Error('copy failed'));
  }

  function copyStatus(button, message) {
    if (!button) return;
    if (button.dataset.copyLabel === undefined) button.dataset.copyLabel = button.textContent;
    button.textContent = message;
    window.setTimeout(function () {
      button.textContent = button.dataset.copyLabel;
    }, 1400);
  }

  var buttons = document.querySelectorAll('.terminal .copy, .cmd button');
  for (var i = 0; i < buttons.length; i++) {
    buttons[i].addEventListener('click', function () {
      var box = this.closest('.terminal') || this.closest('.cmd');
      var code = box ? box.querySelector('code, pre') : null;
      if (!code) return;
      copyText(code.textContent).then(
        function () { copyStatus(this, 'copied'); }.bind(this),
        function () { copyStatus(this, 'copy failed'); }.bind(this)
      );
    });
  }

  function selectInstallTab(tab) {
    var group = tab.closest('[data-install]');
    if (!group) return;
    var scope = group.parentElement || document;
    var all = group.querySelectorAll('[role="tab"]');
    var panels = scope.querySelectorAll('.install-panel');
    var target = tab.getAttribute('aria-controls');

    for (var a = 0; a < all.length; a++) {
      all[a].setAttribute('aria-selected', all[a] === tab ? 'true' : 'false');
      all[a].tabIndex = all[a] === tab ? 0 : -1;
    }
    for (var p = 0; p < panels.length; p++) {
      var active = panels[p].id === target;
      panels[p].classList.toggle('active', active);
      panels[p].hidden = !active;
    }
  }

  var tabs = document.querySelectorAll('.install-tabs [role="tab"]');
  for (var t = 0; t < tabs.length; t++) {
    tabs[t].addEventListener('click', function () { selectInstallTab(this); });
    tabs[t].addEventListener('keydown', function (event) {
      var group = this.closest('[data-install]');
      if (!group) return;
      var all = group.querySelectorAll('[role="tab"]');
      var index = Array.prototype.indexOf.call(all, this);
      var next = -1;
      if (event.key === 'ArrowRight') next = (index + 1) % all.length;
      else if (event.key === 'ArrowLeft') next = (index - 1 + all.length) % all.length;
      else if (event.key === 'Home') next = 0;
      else if (event.key === 'End') next = all.length - 1;
      else return;
      event.preventDefault();
      selectInstallTab(all[next]);
      all[next].focus();
    });
  }

  var nodes = document.querySelectorAll('[data-topology-node]');
  var detail = document.querySelector('[data-topology-detail]');
  if (detail && nodes.length) {
    function selectNode(node) {
      for (var j = 0; j < nodes.length; j++) {
        var on = nodes[j] === node;
        nodes[j].classList.toggle('on', on);
        nodes[j].setAttribute('aria-pressed', on ? 'true' : 'false');
      }
      detail.innerHTML =
        '<h3>' + node.getAttribute('data-name') + '</h3>' +
        '<p>' + node.getAttribute('data-detail') + '</p>' +
        '<p><code>' + node.getAttribute('data-command') + '</code></p>';
    }

    for (var n = 0; n < nodes.length; n++) {
      nodes[n].addEventListener('click', function () { selectNode(this); });
      nodes[n].addEventListener('keydown', function (event) {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          selectNode(this);
        }
      });
    }
    selectNode(nodes[0]);
  }
}());
