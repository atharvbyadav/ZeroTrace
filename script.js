// --- Smooth scrolling for navigation links ---
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener("click", function (e) {
    e.preventDefault();
    const target = document.querySelector(this.getAttribute("href"));
    if (target) {
      target.scrollIntoView({ behavior: "smooth" });
    }
  });
});

// --- Fade-in elements on scroll ---
const faders = document.querySelectorAll('.fade-in');

const appearOptions = {
  threshold: 0.1, // Trigger when 10% of the element is visible
  rootMargin: "0px 0px -50px 0px" // Start loading a bit before it's fully in view
};

const appearOnScroll = new IntersectionObserver(function(
  entries,
  appearOnScroll
) {
  entries.forEach(entry => {
    if (!entry.isIntersecting) {
      return;
    } else {
      entry.target.classList.add('is-visible');
      appearOnScroll.unobserve(entry.target); // Stop observing once visible
    }
  });
},
appearOptions);

faders.forEach(fader => {
  appearOnScroll.observe(fader);
});
