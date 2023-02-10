﻿//  on clicking Comment button from Index, shows or hides the comment input while toggling the button text, tooltip text, icon, and color depending on hidden state. In "Cancel" state a click will also clear the input field.
//! fixme: clear not working anymore, neither is icon
async function ShowCommentBox(id) {
  let commentboxDiv = document.getElementById("commentbox-" + id);
  let btnLink = document.getElementById("comment-link-" + id);
  let commentBtn = document.getElementById("comment-btn-" + id);
  let commentInput = document.getElementById("comment-input" + id);
  let btnIcon = document.getElementById("comment-btn-icon" + id);

  if (commentboxDiv.hasAttribute("hidden")) {
    commentboxDiv.removeAttribute("hidden");
    btnLink.innerHTML = "Cancel";

    commentBtn.setAttribute("data-tooltip", "Cancel your comment");
    commentBtn.classList.remove("btn-transparent");
    commentBtn.classList.add("btn-warning");
    commentBtn.addEventListener("click", () => {
      commentInput.value = "";
    });

    btnIcon.classList.remove("fa-regular", "fa-comment-dots", "fa-xl");
    btnIcon.classList.add("fa-solid", "fa-xmark");
  } else {
    commentboxDiv.hidden = true;

    btnLink.innerHTML = "Comment";

    commentBtn.setAttribute("data-tooltip", "Leave a comment");
    commentBtn.classList.remove("btn-warning");
    commentBtn.classList.add("btn-transparent");

    btnIcon.classList.remove("fa-solid", "fa-xmark");
    btnIcon.classList.add("fa-regular", "fa-comment-dots", "fa-xl");
  }
}

let regBtn = document.getElementById("registerSubmit");
let loginBtn = document.getElementById("login-submit");

async function LogIn() {
  loginBtn.classList.add("loading", "loading-right");
  loginBtn.innerHTML = "Logging In...";
  setTimeout(resetLogin, 3000);
}

async function Register() {
  regBtn.classList.add("loading", "loading-right");
  regBtn.innerHTML = "Registering your account";
  setTimeout(resetReg, 3000);
}

async function resetReg() {
  regBtn.innerHTML = "Register";
  regBtn.classList.remove("loading", "loading-right");
}

async function resetLogin() {
  loginBtn.innerHTML = "Log In";
  loginBtn.classList.remove("loading", "loading-right");
}
