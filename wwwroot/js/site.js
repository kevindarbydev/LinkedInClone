﻿//  on clicking Comment button from Index, shows or hides the comment input while toggling the button text, tooltip text, icon, and color depending on hidden state. In "Cancel" state a click will also clear the input field.

async function ShowCommentBox(id) {
  console.log(id);
  //* change to get by classes OR add id to each id
  let commentboxDiv = document.getElementById("commentbox-" + id);
  let btnLink = document.getElementById("comment-link");
  let commentBtn = document.getElementById("comment-btn-" + id);
  let commentInput = document.getElementById("comment-input");
  let btnIcon = document.getElementById("comment-btn-icon");

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
