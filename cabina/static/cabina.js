// Aiuti dell'interfaccia della scheda.
//
// Servono solo a rendere comoda la compilazione: una preferenza segna
// la sua lista, le preferenze di altre liste vengono tolte, i limiti
// R4 e R5 vengono segnalati. La validità della scheda non dipende da
// questo codice ma dalle prove: con "dispositivo scorretto" questi
// controlli si spengono e la bacheca rifiuta comunque la scheda.

(function () {
  "use strict";

  var form = document.getElementById("scheda");

  if (!form) {
    return;
  }

  var maxPreferences = Number(form.dataset.max);
  var maxPerGender = Number(form.dataset.maxGender);
  var notice = document.getElementById("avviso");
  var faulty = document.getElementById("scorretto");

  function preferences() {
    return Array.prototype.slice.call(
      form.querySelectorAll('input[name="preferenze"]')
    );
  }

  function listRadios() {
    return Array.prototype.slice.call(
      form.querySelectorAll('input[name="lista"]')
    );
  }

  function warn(message) {
    notice.textContent = message;
    notice.hidden = !message;
  }

  function highlight() {
    listRadios().forEach(function (radio) {
      var card = radio.closest(".list-card");

      if (card) {
        card.classList.toggle("selected", radio.checked);
      }
    });
  }

  function selectList(value) {
    listRadios().forEach(function (radio) {
      radio.checked = radio.value === value;
    });
  }

  function clearOtherLists(value) {
    preferences().forEach(function (box) {
      if (box.dataset.list !== value) {
        box.checked = false;
      }
    });
  }

  function checkLimits(changed) {
    var chosen = preferences().filter(function (box) {
      return box.checked;
    });

    if (chosen.length > maxPreferences) {
      changed.checked = false;
      warn("Al massimo " + maxPreferences + " preferenze (regola R4).");
      return;
    }

    var sameGender = chosen.filter(function (box) {
      return box.dataset.gender === changed.dataset.gender;
    });

    if (sameGender.length > maxPerGender) {
      changed.checked = false;
      warn(
        "Al massimo " + maxPerGender +
        " preferenze dello stesso genere (regola R5)."
      );
      return;
    }

    warn("");
  }

  preferences().forEach(function (box) {
    box.addEventListener("change", function () {
      if (faulty.checked) {
        return;
      }

      if (box.checked) {
        selectList(box.dataset.list);
        clearOtherLists(box.dataset.list);
        checkLimits(box);
      }

      highlight();
    });
  });

  listRadios().forEach(function (radio) {
    radio.addEventListener("change", function () {
      if (!faulty.checked) {
        clearOtherLists(radio.value);
        warn("");
      }

      highlight();
    });
  });

  faulty.addEventListener("change", function () {
    warn(
      faulty.checked
        ? "Controlli dell'interfaccia disattivati: ora decidono solo le prove."
        : ""
    );
  });
})();
