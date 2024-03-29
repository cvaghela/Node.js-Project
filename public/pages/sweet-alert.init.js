/**
 * Theme: Upbond
 * SweetAlert
 */


! function(e) {
  "use strict";
  var t = function() {};
  t.prototype.init = function() {
    e("#sa-basic").on("click", function() {
      swal("Here's a message!")
    }), e("#sa-title").on("click", function() {
      swal("Here's a message!", "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed lorem erat, tincidunt vitae ipsum et, pellentesque maximus enim. Mauris eleifend ex semper, lobortis purus sed, pharetra felis")
    }), e("#sa-success").on("click", function() {
      swal("Good job!", "You have successfully Logged In!", "success")
    }), e("#sa-warning").on("click", function() {
      swal({
        title: "Are you sure?",
        text: "You will not be able to recover this imaginary file!",
        type: "warning",
        showCancelButton: !0,
        confirmButtonClass: "btn-warning",
        confirmButtonText: "Yes, delete it!",
        closeOnConfirm: !1
      }, function() {
        swal("Deleted!", "Your imaginary file has been deleted.", "success")
      })
    }), e("#sa-params").on("click", function() {
      swal({
        title: "Are you sure?",
        text: "You will not be able to recover this imaginary file!",
        type: "warning",
        showCancelButton: !0,
        confirmButtonColor: "#DD6B55",
        confirmButtonText: "Yes, delete it!",
        cancelButtonText: "No, cancel plx!",
        closeOnConfirm: !1,
        closeOnCancel: !1
      }, function(e) {
        e ? swal("Deleted!", "Your imaginary file has been deleted.", "success") : swal("Cancelled", "Your imaginary file is safe :)", "error")
      })
    }), e("#sa-image").on("click", function() {
      swal({
        title: "Sweet!",
        text: "Here's a custom image.",
        imageUrl: "assets/plugins/bootstrap-sweetalert/thumbs-up.jpg"
      })
    }), e("#sa-close").on("click", function() {
      swal({
        title: "Auto close alert!",
        text: "I will close in 2 seconds.",
        timer: 2e3,
        showConfirmButton: !1
      })
    })
  }, e.SweetAlert = new t, e.SweetAlert.Constructor = t
}(window.jQuery),
function(e) {
  "use strict";
  e.SweetAlert.init()
}(window.jQuery);