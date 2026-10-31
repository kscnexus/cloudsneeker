/* Cloudsneeker marketing site: theme toggle, header state, mobile menu,
   reveal on scroll, product tour tabs, and the contact form (mailto only,
   no network requests, no tracking). Every feature is an enhancement: the
   pages are complete and readable without this file. */
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
      buttons[i].setAttribute("aria-label", isLight ? "Switch to dark theme" : "Switch to light theme");
    }
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", isLight ? "#f6f8fc" : "#050912");
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

  // Header: compact with a border once the page scrolls.
  var header = document.querySelector(".site-header");
  if (header) {
    var ticking = false;
    var updateHeader = function () {
      header.classList.toggle("is-scrolled", window.scrollY > 8);
      ticking = false;
    };
    window.addEventListener(
      "scroll",
      function () {
        if (!ticking) {
          ticking = true;
          window.requestAnimationFrame(updateHeader);
        }
      },
      { passive: true }
    );
    updateHeader();
  }

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
    nav.addEventListener("click", function (event) {
      if (event.target.closest("a")) setOpen(false);
    });
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && nav.classList.contains("is-open")) {
        setOpen(false);
        menuButton.focus();
      }
    });
    window.addEventListener("resize", function () {
      if (window.innerWidth > 980) setOpen(false);
    });
  }

  // Reveal on scroll. Content is visible by default; only items that start
  // below the fold are hidden, and only while the observer is working.
  var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var revealItems = Array.prototype.slice.call(document.querySelectorAll(".reveal"));
  if (!reduceMotion && "IntersectionObserver" in window && revealItems.length) {
    var showAll = function () {
      revealItems.forEach(function (el) {
        el.classList.remove("is-pending");
      });
    };
    var fired = false;
    var observer = new IntersectionObserver(
      function (entries) {
        fired = true;
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.remove("is-pending");
            observer.unobserve(entry.target);
          }
        });
      },
      { rootMargin: "0px 0px 20% 0px", threshold: 0 }
    );
    var fold = window.innerHeight || document.documentElement.clientHeight;
    revealItems.forEach(function (el, i) {
      if (el.getBoundingClientRect().top > fold * 0.92) {
        el.classList.add("is-pending");
        // Small stagger for siblings in the same row.
        el.style.transitionDelay = (i % 3) * 70 + "ms";
        observer.observe(el);
      }
    });
    // Safety nets: if the observer never reports, or the page is printed,
    // show everything.
    window.setTimeout(function () {
      if (!fired) showAll();
    }, 1200);
    window.setTimeout(showAll, 6000);
    window.addEventListener("beforeprint", showAll);
  }

  // Product tour tabs (WAI-ARIA tabs pattern, automatic activation).
  var tablists = document.querySelectorAll("[data-tabs]");
  Array.prototype.forEach.call(tablists, function (wrap) {
    var tabs = Array.prototype.slice.call(wrap.querySelectorAll('[role="tab"]'));
    if (!tabs.length) return;
    var select = function (tab, focus) {
      tabs.forEach(function (t) {
        var on = t === tab;
        t.setAttribute("aria-selected", on ? "true" : "false");
        t.tabIndex = on ? 0 : -1;
        var panel = document.getElementById(t.getAttribute("aria-controls"));
        if (panel) panel.hidden = !on;
      });
      if (focus) tab.focus();
    };
    tabs.forEach(function (tab, index) {
      tab.addEventListener("click", function () {
        select(tab, false);
      });
      tab.addEventListener("keydown", function (event) {
        var next = null;
        if (event.key === "ArrowDown" || event.key === "ArrowRight") next = tabs[(index + 1) % tabs.length];
        else if (event.key === "ArrowUp" || event.key === "ArrowLeft") next = tabs[(index - 1 + tabs.length) % tabs.length];
        else if (event.key === "Home") next = tabs[0];
        else if (event.key === "End") next = tabs[tabs.length - 1];
        if (next) {
          event.preventDefault();
          select(next, true);
        }
      });
    });
    var initial = tabs.filter(function (t) {
      return t.getAttribute("aria-selected") === "true";
    })[0] || tabs[0];
    select(initial, false);
    wrap.classList.add("tabs-ready");
  });

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
        "mailto:" + to + "?subject=" + encodeURIComponent(subject) + "&body=" + encodeURIComponent(lines.join("\r\n"));
      window.location.href = href;
      if (status) {
        status.textContent =
          "Your email app should open with the message ready to send. If nothing happens, write to " + to + ".";
      }
    });
  }

  // Preselect the free audit topic when arriving from an audit link.
  var interest = document.getElementById("interest");
  if (interest) {
    try {
      if (new URLSearchParams(window.location.search).get("topic") === "audit") {
        interest.value = "Free cloud security audit";
      }
    } catch (e) {
      /* older browsers: leave the default topic */
    }
  }
})();
