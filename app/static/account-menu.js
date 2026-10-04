// Self-service account controls. Passwords stay in the form and request body;
// they are never kept in Alpine state or browser storage.
(function () {
  'use strict';

  window.accountMenu = function () {
    return {
      open: false,
      email: '',
      mode: 'email',
      busy: false,
      error: '',
      success: false,
      needsLogin: false,

      init() {
        this.email = this.$el.dataset.email;
      },

      description() {
        if (this.success) {
          return this.mode === 'email'
            ? 'Use your new email address the next time you sign in.'
            : 'Your password has been changed and all sessions have ended. Sign in again with your new password.';
        }
        return this.mode === 'email'
          ? 'Update your sign-in email. Confirm your current password to save the change.'
          : 'Choose a new password for your account. This will sign you out on all devices.';
      },

      async edit(mode) {
        this.open = false;
        this.mode = mode;
        this.error = '';
        this.success = false;
        this.needsLogin = false;
        this.$refs.form.reset();
        // x-if must create the selected fields before showModal chooses its focus.
        await this.$nextTick(() => {
          // reset() restores defaultValue, whereas Alpine's :value only sets value.
          this.$refs.form.elements.namedItem('username').value = this.email;
          this.$refs.dialog.showModal();
          this.$refs.form.elements.namedItem(mode === 'email' ? 'email' : 'current_password').focus();
        });
      },

      closeDialog() {
        if (this.busy) return;
        if (this.needsLogin) {
          window.location.href = '/auth/login';
          return;
        }
        this.$refs.dialog.close();
      },

      dialogClosed() {
        this.$refs.form.reset();
        this.error = '';
        this.$refs.trigger.focus();
      },

      async fail(message, field) {
        this.error = message;
        await this.$nextTick(() => {
          const target = field && this.$refs.form.elements.namedItem(field);
          (target || this.$refs.error).focus();
        });
      },

      async save() {
        if (this.busy || this.success || this.needsLogin) return;
        const values = new FormData(this.$refs.form);
        const current = values.get('current_password');
        if (!current) return this.fail('Enter your current password to confirm this change.', 'current_password');
        const payload = { current_password: current };
        if (this.mode === 'email') {
          payload.email = values.get('email').trim();
          if (payload.email.toLowerCase() === this.email.toLowerCase()) {
            return this.fail('Enter a different email address.', 'email');
          }
        } else {
          payload.password = values.get('password');
          if (payload.password !== values.get('confirm_password')) {
            return this.fail('The new passwords do not match.', 'confirm_password');
          }
        }

        this.busy = true;
        this.error = '';
        try {
          const response = await fetch('/api/users/me', {
            method: 'PATCH',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          });
          const data = await response.json().catch(() => null);
          this.busy = false;
          if (response.ok) {
            if (this.mode === 'email') this.email = data.email;
            this.success = true;
            this.needsLogin = this.mode === 'password';
            this.$refs.form.reset();
            await this.$nextTick(() => this.$refs.done.focus());
          } else if (response.status === 401) {
            this.needsLogin = true;
            this.$refs.form.reset();
            await this.fail('Your session has expired. Sign in again to change your account.');
          } else if (response.status === 429) {
            await this.fail('Too many attempts. Wait a moment and try again.');
          } else if (response.status === 403) {
            await this.fail('The request could not be verified. Reload the page and try again.');
          } else if (data?.detail === 'UPDATE_USER_EMAIL_ALREADY_EXISTS') {
            await this.fail('This email address is already in use. Choose another email.', 'email');
          } else if (data?.detail?.code === 'UPDATE_USER_INVALID_PASSWORD') {
            // Only the password-policy reason is safe to show; validation responses
            // can contain submitted input, including passwords. x-text renders prose.
            const reason = data.detail.reason;
            if (typeof reason === 'string' && reason.includes('current password')) {
              await this.fail('Your current password is incorrect. Please try again.', 'current_password');
            } else {
              await this.fail(typeof reason === 'string' ? reason : 'Choose a stronger password.', 'password');
            }
          } else if (response.status === 422) {
            await this.fail(this.mode === 'email' ? 'Enter a valid email address.' : 'Check your password entries and try again.');
          } else {
            await this.fail('Could not save your changes. Please try again.');
          }
        } catch (_) {
          this.busy = false;
          await this.fail('Could not confirm the change. Check your connection before trying again.');
        } finally {
          this.busy = false;
        }
      },
    };
  };
})();
