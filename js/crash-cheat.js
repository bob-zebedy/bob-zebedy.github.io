window.onload = function () {
  var originalTitle = document.title;
  var titleTimer;

  function setIcon(iconPath) {
    $('[rel="icon"], [rel="shortcut icon"]').attr("href", iconPath);
  }

  document.addEventListener("visibilitychange", function () {
    clearTimeout(titleTimer);

    if (document.hidden) {
      setIcon("/images/crash.ico");
      document.title = "喔唷，崩溃啦!  ";
    } else {
      setIcon("/images/avatar.ico");
      if (document.title !== originalTitle) {
        document.title = "♪(^∇^*) 噫? 又好了!  ";
        titleTimer = setTimeout(function () {
          if (!document.hidden) {
            document.title = originalTitle;
          }
        }, 2000);
      }
    }
  });
};
