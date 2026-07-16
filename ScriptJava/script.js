// search overlay
  const searchBtn = document.getElementById('searchBtn');
  const searchOverlay = document.getElementById('searchOverlay');
  const searchClose = document.getElementById('searchClose');
  searchBtn.addEventListener('click', () => {
    searchOverlay.classList.add('open');
    searchOverlay.querySelector('input').focus();
  });
  searchClose.addEventListener('click', () => searchOverlay.classList.remove('open'));
  document.addEventListener('keydown', (e) => { if(e.key === 'Escape') searchOverlay.classList.remove('open'); });

  // mobile menu
  const menuBtn = document.getElementById('menuBtn');
  const mobileMenu = document.getElementById('mobileMenu');
  menuBtn.addEventListener('click', () => mobileMenu.classList.toggle('open'));
  mobileMenu.querySelectorAll('a').forEach(a => a.addEventListener('click', () => mobileMenu.classList.remove('open')));

  // interactive keycap
  const cap = document.getElementById('pressCap');
  const press = () => {
    cap.classList.add('pressed');
    setTimeout(() => cap.classList.remove('pressed'), 160);
  };
  cap.addEventListener('mousedown', press);
  cap.addEventListener('touchstart', press);