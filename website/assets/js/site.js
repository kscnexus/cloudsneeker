/* Cloudsneeker marketing site: theme toggle, mobile menu, reveal on scroll,
   and the contact form (mailto only, no network requests, no tracking). */
(function () {
  "use strict";

  var root = document.documentElement;
  var STORAGE_KEY = "cloudsneeker-theme";

  function readStored() {
    try {
      return window.localStorage.getItem(STORAGE_KEY);
    } catch (e) {
      return null;
    }
  }

  function store(value) {
    try {
      window.localStorage.setItem(STORAGE_KEY, value);
    } catch (e) {
      /* Storage blocked: the choice lasts for this page only. */
    }
  }

  function currentTheme() {
    return root.getAttribute("data-theme") === "light" ? "light" : "dark";
  }

  function syncToggle() {
    var buttons = document.querySelectorAll("[data-theme-toggle]");
    var isLight = currentTheme() === "light";
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].setAttribute("aria-pressed", isLight ? "true" : "false");
      buttons[i].setAttribute(
        "aria-label",
        isLight ? "Switch to dark theme" : "Switch to light theme"
      );
    }
  }

  // Theme toggle
  document.addEventListener("click", function (event) {
    var button = event.target.closest && event.target.closest("[data-theme-toggle]");
    if (!button) return;
    var next = currentTheme() === "light" ? "dark" : "light";
    root.setAttribute("data-theme", next);
    store(next);
    syncToggle();
  });

  // Follow OS changes only when the visitor has not picked a theme.
  if (window.matchMedia) {
    var mq = window.matchMedia("(prefers-color-scheme: light)");
    var onChange = function (e) {
      if (readStored()) return;
      root.setAttribute("data-theme", e.matches ? "light" : "dark");
      syncToggle();
    };
    if (mq.addEventListener) mq.addEventListener("change", onChange);
    else if (mq.addListener) mq.addListener(onChange);
  }

  syncToggle();

  // Mobile menu
  var menuButton = document.querySelector("[data-menu-toggle]");
  var nav = document.getElementById("primary-nav");
  if (menuButton && nav) {
    var setOpen = function (open) {
      nav.classList.toggle("is-open", open);
      menuButton.setAttribute("aria-expanded", open ? "true" : "false");
      menuButton.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    };
    menuButton.addEventListener("click", function () {
      setOpen(menuButton.getAttribute("aria-expanded") !== "true");
    });
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && nav.classList.contains("is-open")) {
        setOpen(false);
        menuButton.focus();
      }
    });
    window.addEventListener("resize", function () {
      if (window.innerWidth > 880) setOpen(false);
    });
  }

  // Reveal on scroll
  var reduceMotion =
    window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var revealItems = document.querySelectorAll(".reveal");
  if (!reduceMotion && "IntersectionObserver" in window) {
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.08 }
    );
    revealItems.forEach(function (el) {
      observer.observe(el);
    });
  } else {
    revealItems.forEach(function (el) {
      el.classList.add("is-visible");
    });
  }

  // Footer year
  var yearEls = document.querySelectorAll("[data-year]");
  for (var y = 0; y < yearEls.length; y++) {
    yearEls[y].textContent = String(new Date().getFullYear());
  }

  // Contact form: compose an email in the visitor's mail app.
  var form = document.getElementById("contact-form");
  if (form) {
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var status = document.getElementById("form-status");
      if (!form.checkValidity()) {
        form.reportValidity();
        return;
      }
      var to = form.getAttribute("data-mailto");
      var data = new FormData(form);
      var interest = data.get("interest") || "General enquiry";
      var subject = "Cloudsneeker enquiry: " + interest;
      var lines = [
        "Name: " + (data.get("name") || ""),
        "Work email: " + (data.get("email") || ""),
        "Company: " + (data.get("company") || ""),
        "Role: " + (data.get("role") || ""),
        "Interested in: " + interest,
        "Clouds in use: " + (data.get("clouds") || ""),
        "",
        String(data.get("message") || ""),
      ];
      var href =
        "mailto:" +
        to +
        "?subject=" +
        encodeURIComponent(subject) +
        "&body=" +
        encodeURIComponent(lines.join("\r\n"));
      window.location.href = href;
      if (status) {
        status.textContent =
          "Your email app should open with the message ready to send. If nothing happens, write to " +
          to +
          ".";
      }
    });
  }
})();
